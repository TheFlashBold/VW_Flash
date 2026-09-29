"""
Bosch EDC17 (VAG diesel, TC1767/TC1797) — same Gen1 platform as MED17.5.

Reverse-engineered / verified members: EDC17C46 (2 MB TC1767), EDC17C54 (4 MB
TC1797). Both share the MED17.5 family's mechanisms:

  * CRC "TPROT" — the family-universal CRC-32 RESIDUE scheme
    (crc32_med175(region, 0xFADECAFE) == 0xCAFEAFFE), reused from med175. Only
    the block RANGES differ per ECU (see edc17_crc_ranges). No RSA/signature.
    An AES forward S-box IS present, but its whole call-graph is a self-contained
    ASW diagnostic/SecurityAccess cluster (EDC17C54: FUN_801722fc <- FUN_8017247a
    <- FUN_800ce0e2) with NO path from the bootblock/flash-loader — it is NOT a
    flash/boot CMAC. Flash integrity is CRC-only.

  * SA2 seed/key — the VAG SA2 bytecode VM ("BiWbBuD101"), but the SCRIPT is
    PER-ECU (constants differ; VAGFlasher's single hardcoded Feistel is wrong for
    all of them). Scripts extracted from flash next to the "BiWbBuD101" string,
    keys cross-checked with sa2_seed_key.Sa2SeedKey.

Scope: SA2 + CRC ranges/check. UDS flash-procedure fields (block ids, transfer
sizes, RequestUpload availability) are not reversed here.
"""
from lib.crypto.plaintext import PlaintextCrypto
from lib.modules.med175 import (
    sa2_key,
    crc32_med175,
    crc_ok_med175,
    crc_fix_word_med175,
    MED175_CRC_INIT,
    MED175_CRC_RESIDUE,
)

# ─────────────────────────────────────────────────────────────────────────────
# SA2 seed/key — per-ECU bytecode script (same VAG SA2 VM)
# ─────────────────────────────────────────────────────────────────────────────

# EDC17C46: FOR 17 { XOR 0x02C11DB7; SUB 0xC0F23A51 (carry=borrow);
#   if borrow: r=ROR(r)  else: r=ROL(r); r += 0x030C0170 }
sa2_script_edc17c46 = bytes.fromhex("68118702C11DB784C0F23A514A03826B068193030C0170494C")


def sa2_key_edc17c46(seed: int) -> int:
    """EDC17C46 SA2 seed->key. e.g. 0x12345678 -> 0xB6012B32, 0xDEADBEEF -> 0x5F7AC9C6.
    Script decodes to: FOR 17 { XOR 0x02C11DB7; SUB 0xC0F23A51 (carry=borrow);
    if borrow: ROR else: ROL, ADD 0x030C0170 }."""
    return sa2_key(sa2_script_edc17c46, seed)


# EDC17C54: FOR 7 { ADD 0xF2595836 (carry=overflow);
#   if overflow: r -= 0x19821216; r=ROR(r)  else: r ^= 0x5698EFBA; r=ROL(r) }
sa2_script_edc17c54 = bytes.fromhex("680793F25958364A088419821216826B06875698EFBA81494C")


def sa2_key_edc17c54(seed: int) -> int:
    """EDC17C54 SA2 seed->key. e.g. 0x12345678 -> 0xC6ED8952, 0xDEADBEEF -> 0xF8E2F311.
    Script decodes to: FOR 7 { ADD 0xF2595836 (carry=overflow);
    if overflow: SUB 0x19821216, ROR else: XOR 0x5698EFBA, ROL }."""
    return sa2_key(sa2_script_edc17c54, seed)


# EDC17CP54 — TC1793, BANKED (PMU0 @0x80000000, PMU1 @0x80800000). VW Amarok V6
# 3.0 TDI (2H6907311* / 059907309J). SA2 is per-SOFTWARE-LINE, not one per ECU:
#   * C1556AP* line (e.g. C1556APIB/APE5): 8 MB reads
#   * C1556AQ* line (e.g. C1556AQO0/AQI0): 4 MB reads
sa2_script_edc17cp54_ap = bytes.fromhex("680787A0B1C2D393149330AC4A03826B068193830DE7658443F96124494C")
sa2_script_edc17cp54_aq = bytes.fromhex("6807871012202293110120234A03826B068193120220248413032025494C")


def sa2_key_edc17cp54_ap(seed: int) -> int:
    """EDC17CP54 C1556AP* line SA2. e.g. 0x12345678 -> 0x75B1ACDD."""
    return sa2_key(sa2_script_edc17cp54_ap, seed)


def sa2_key_edc17cp54_aq(seed: int) -> int:
    """EDC17CP54 C1556AQ* line SA2. e.g. 0x12345678 -> 0x535F4085."""
    return sa2_key(sa2_script_edc17cp54_aq, seed)


# EDC17CP54 (TC1793) address -> file-offset map for CRC checks: bank1 is stored
# right after bank0's 2 MB. Works for both the 4 MB and 8 MB reads.
def edc17cp54_addr_to_file(addr: int) -> int | None:
    if 0x80000000 <= addr < 0x80200000:
        return addr - 0x80000000                 # PMU0
    if 0x80800000 <= addr < 0x80A00000:
        return addr - 0x80800000 + 0x200000       # PMU1 -> file 0x200000+
    return None


# ─────────────────────────────────────────────────────────────────────────────
# CRC-checked ranges per ECU (inclusive [start, end]); all residue-verified
# (crc32_med175(range, 0xFADECAFE) == 0xCAFEAFFE against the stock images).
# ─────────────────────────────────────────────────────────────────────────────
edc17_crc_ranges = {
    # EDC17C46 — 2 MB TC1767 (e.g. DX55ZDCUJ0000).
    "edc17c46": [
        (0x80000000, 0x80003FFB),  # vectors
        (0x80004000, 0x8000FEFB),  # bootblock
        (0x80018000, 0x8001FEFB),
        (0x8001FF00, 0x8001FFDF),
        (0x80020000, 0x8017FFFB),  # ASW (~1.4 MB)
        (0x80180000, 0x8019FEFB),  # CAL/data
    ],
    # EDC17C54 — 4 MB TC1797 flat (e.g. VW Amarok 2.0 BiTDi).
    "edc17c54": [
        (0x80000000, 0x80003FFB),  # vectors
        (0x80004000, 0x8000FEFB),  # bootblock
        (0x80010000, 0x80013FFB),
        (0x80014000, 0x80017EFB),
        (0x80018000, 0x8001FEFB),
        (0x8001FF00, 0x8001FFDF),
        (0x80020000, 0x8027FFFB),  # ASW (2.5 MB)
        (0x80283000, 0x8037FEFB),  # ASW/data
        (0x80380000, 0x803FFFFB),  # CAL/data
    ],
    # EDC17CP54 — TC1793 BANKED (use edc17cp54_addr_to_file for offsets).
    "edc17cp54": [
        (0x80000000, 0x8000FFFB),  # PMU0: boot region (64 KB block)
        (0x80010000, 0x80013FFB),
        (0x80014000, 0x80017EFB),
        (0x80018000, 0x8001FEFB),
        (0x8001FF00, 0x8001FFDF),
        (0x80020000, 0x801FFFFB),  # PMU0 ASW (~2 MB)
        (0x80800000, 0x80817EFB),  # PMU1
        (0x80818000, 0x808BFFFB),
        (0x808C0000, 0x809E6FFB),  # present on 4 MB reads; skipped if out of range
        (0x809E7000, 0x809FFEFB),  # PMU1 CAL/data
    ],
}

# variant -> (default SA2 script, default SA2 key fn). CP54 has two software lines;
# pick per software id (C1556AP* vs C1556AQ*).
edc17_sa2 = {
    "edc17c46": (sa2_script_edc17c46, sa2_key_edc17c46),
    "edc17c54": (sa2_script_edc17c54, sa2_key_edc17c54),
    "edc17cp54_ap": (sa2_script_edc17cp54_ap, sa2_key_edc17cp54_ap),
    "edc17cp54_aq": (sa2_script_edc17cp54_aq, sa2_key_edc17cp54_aq),
}

# variant -> address->file-offset mapping (default: flat). CP54 is banked.
edc17_addr_map = {
    "edc17cp54": edc17cp54_addr_to_file,
}

edc17_crypto = PlaintextCrypto()  # blocks are plaintext; AES is ASW-diag only


def edc17_check_ranges(data: bytes, variant: str) -> list[tuple[int, int, bool]]:
    """Verify every CRC range of `variant` against `data`. Returns (start, end, ok)
    per range. Uses the banked address map for CP54, flat otherwise."""
    to_file = edc17_addr_map.get(variant, lambda a: a - 0x80000000)
    out = []
    for start, end in edc17_crc_ranges[variant]:
        so = to_file(start)
        eo = to_file(end)
        ok = so is not None and eo is not None and 0 <= so and eo < len(data) and crc_ok_med175(data[so:eo + 1])
        out.append((start, end, ok))
    return out
