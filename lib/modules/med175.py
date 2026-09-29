"""
Bosch MED17.5 family — COMMON module (MED17.5 / MED17.5.1 / MED17.5.5).

This module is the shared home of the MED17.5 family and the default FlashInfo
for the COMMON members (17.5, 17.5.1, 17.5.5), which all share one SA2 script.
MED17.5.2 is the odd one out (different SA2 + all-internal TC1767 layout) and
lives in its own module, med1752.py.

  * SA2 seed/key — COMMON variant, byte-identical across 17.5 / 17.5.1 / 17.5.5:
        6805814A05870A221289494C
        FOR 5 { carry = MSB(r); r = ROL(r,1); if carry: r ^= 0x0A221289 }
        e.g. 0x12345678 -> 0x52CEEA10, 0xDEADBEEF -> 0x38E056B8
    (VM/library-computed; MED17.5.2's own script is harness-validated in med1752.)
    NOTE: dspl1236/VAGFlasher's "BiWbBuD101" (5-round Feistel, const 0x1A76B3C4)
    is FABRICATED — that constant is absent from every image. Use these scripts.

  * CRC — FAMILY-UNIVERSAL residue scheme (crc32_med175 / crc_ok_med175 /
    crc_fix_word_med175, init 0xFADECAFE -> residue 0xCAFEAFFE). Reverse-engineered
    from the descriptor walker FUN_8000947e and verified on all four variants.
    Only the block RANGES differ per layout (see med175_crc_ranges_by_variant).

  * Blocks are PLAINTEXT (no AES/RSA); integrity is the keyless CRC-32 residue.

The default FlashInfo below is the TC1766 1.5 MB layout (MED17.5 / MED17.5.5).
Only the blocks written by the OBD .sgo/.frf container are modelled: BLK_04000
(bootblock/loader), BLK_20000 (program), CAL, ASW. Blocks that exist in a full
chip read but are not in the OBD container (vectors, blk14000, blk18000,
blk18ff00) are omitted, as is the phantom 0x10000 (17.5.2-only).

MED17.5.1 shares the common SA2 but is split across a small INTERNAL flash
(micro.bin @0x80000000, holding the bootblock) and a SEPARATE 4 MB EXTERNAL SPI
flash (ext flash.bin @0x80800000) that holds the real ASW (0x80820000) + CAL
(0x809C0000). Its OBD container (e.g. 03C906032*) writes exactly {bootblock,
ext_ASW, ext_CAL} — see the tc1767_ext range set. MED17.5.2 -> med1752.py.
"""
from sa2_seed_key.sa2_seed_key import Sa2SeedKey

from lib.constants import (
    FlashInfo,
    ControlModuleIdentifier,
)
from lib.crypto.plaintext import PlaintextCrypto


def sa2_key(script: bytes, seed: int) -> int:
    """Run a VAG SA2 bytecode script (seed -> key) via the repo's Sa2SeedKey VM.
    Shared by every Bosch Gen1 module (MED17.5 family + EDC17)."""
    return Sa2SeedKey(script, seed & 0xFFFFFFFF).execute() & 0xFFFFFFFF


# ─────────────────────────────────────────────────────────────────────────────
# Family-universal CRC-32 residue scheme (shared by every MED17.5 module).
# ─────────────────────────────────────────────────────────────────────────────
_CRC32_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC32_TABLE.append(_c)

MED175_CRC_INIT = 0xFADECAFE      # FE CA DE FA in flash (the "FECADEFA" magic)
MED175_CRC_RESIDUE = 0xCAFEAFFE   # FE AF FE CA in flash (the "CAFEAFFE" magic)


def crc32_med175(data: bytes, init: int = 0xFFFFFFFF) -> int:
    """Exact algorithm of the on-ECU routine FUN_80008c36 (harness-verified):
    table-driven CRC-32, poly 0xEDB88320, reflected, returns ~crc. `init` is a
    parameter. For init=0xFADECAFE this is the block-integrity check."""
    crc = init & 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32_TABLE[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF


def crc_ok_med175(region: bytes) -> bool:
    """True if `region` (exact [start..end] bytes of a block) passes the ECU
    check: crc32_med175(region, 0xFADECAFE) == 0xCAFEAFFE."""
    return crc32_med175(region, MED175_CRC_INIT) == MED175_CRC_RESIDUE


def crc_fix_word_med175(region: bytearray, corr_off: int) -> int:
    """Return the 4-byte little-endian value to write at `corr_off` (a 4-byte
    slot inside `region`) so the whole region satisfies the residue check.

    CRC-32 is affine, so patching the 32-bit word at corr_off changes the output
    linearly. This solves (over GF(2)) for the word that makes
    crc32_med175(region, 0xFADECAFE) == 0xCAFEAFFE."""
    r = bytearray(region)
    for i in range(4):
        r[corr_off + i] = 0
    base = crc32_med175(bytes(r), MED175_CRC_INIT)
    need = base ^ MED175_CRC_RESIDUE

    def _with_word(w: int) -> int:
        r2 = bytearray(r)
        r2[corr_off] = w & 0xFF
        r2[corr_off + 1] = (w >> 8) & 0xFF
        r2[corr_off + 2] = (w >> 16) & 0xFF
        r2[corr_off + 3] = (w >> 24) & 0xFF
        return crc32_med175(bytes(r2), MED175_CRC_INIT) ^ base

    rows = [(1 << b, _with_word(1 << b)) for b in range(32)]
    sol = 0
    for bitpos in range(31, -1, -1):
        piv = next((i for i in range(len(rows)) if (rows[i][1] >> bitpos) & 1), None)
        if piv is None:
            continue
        rows[piv], rows[0] = rows[0], rows[piv]
        p_in, p_out = rows[0]
        for i in range(1, len(rows)):
            if (rows[i][1] >> bitpos) & 1:
                rows[i] = (rows[i][0] ^ p_in, rows[i][1] ^ p_out)
        if (need >> bitpos) & 1:
            need ^= p_out
            sol ^= p_in
        rows = rows[1:]
    return sol & 0xFFFFFFFF


# CRC-checked ranges per layout (inclusive [start, end]) — ONLY the blocks that
# are present in the OBD .sgo/.frf flash container are listed (all residue-
# verified: crc32_med175(range, 0xFADECAFE) == 0xCAFEAFFE). Blocks that exist in
# a full chip read but are NOT written by the OBD container are omitted: vectors
# @0x0, blk14000, blk18000, blk18ff00, and (on 17.5.1) the bootblock mirror
# @0x44000. NB: base MED17.5 has no 0x10000 block at all (that is 17.5.2-only).
med175_crc_ranges_by_variant = {
    # MED17.5 / MED17.5.5 — TC1766, 1.5 MB internal. OBD container
    # (e.g. 1P0907115AE, D175X56H) = {bootblock, blk20000, CAL, ASW}.
    "tc1766": {
        "bootblock": (0x80004000, 0x8000FEFB),  # flash loader
        "blk20000":  (0x80020000, 0x8003FFFB),  # program block
        "CAL":       (0x80040000, 0x8007FFFB),  # calibration (MED17.5.5 banner @0x8005D434)
        "ASW":       (0x80080000, 0x80177FFB),
    },
    # MED17.5.1 — TC1767 + EXTERNAL SPI flash. OBD container (e.g. 03C906032*,
    # D175X52H) = {bootblock (internal @0x80000000), ext_ASW, ext_CAL (both in
    # the external flash mapped @0x80800000 — its own ext flash.bin, extract
    # separately)}.
    "tc1767_ext": {
        "bootblock": (0x80004000, 0x8000FCFF),  # internal micro flash
        "ext_ASW":   (0x80820000, 0x809BFEFF),  # external SPI flash (~1.6 MB ASW)
        "ext_CAL":   (0x809C0000, 0x809FFEFF),  # external SPI flash (256 KB CAL)
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# COMMON SA2 (MED17.5 / MED17.5.1 / MED17.5.5)
# ─────────────────────────────────────────────────────────────────────────────
sa2_script_med175 = bytes.fromhex("6805814A05870A221289494C")


def sa2_key_med175(seed: int) -> int:
    """MED17.5 / 17.5.1 / 17.5.5 SA2 seed -> key (script 6805814A05870A221289494C).

    Script decodes to: FOR 5 { carry = MSB(r); r = ROL(r,1); if carry: r ^= 0x0A221289 }.
    e.g. 0x12345678 -> 0x52CEEA10, 0xDEADBEEF -> 0x38E056B8.
    """
    return sa2_key(sa2_script_med175, seed)


# ─────────────────────────────────────────────────────────────────────────────
# Default FlashInfo = MED17.5 / MED17.5.5 (TC1766, 1.5 MB).
# ─────────────────────────────────────────────────────────────────────────────
med175_crc_ranges = med175_crc_ranges_by_variant["tc1766"]

# Block set for base MED17.5 (TC1766) = exactly the OBD .sgo/.frf container:
# bootblock (loader) + program block @0x20000 + CAL + ASW. Blocks that exist in
# a full chip read but are NOT written by the OBD container (vectors, blk14000,
# blk18000, blk18ff00) and the phantom 0x10000 (17.5.2-only) are omitted.
block_names_frf_med175 = {
    1: "BLK_04000",  # bootblock / flash loader (0x04000..0x0FEFF)
    2: "BLK_20000",  # program block
    3: "CAL",
    4: "ASW",
}

base_addresses_med175 = {
    1: 0x80004000,
    2: 0x80020000,
    3: 0x80040000,
    4: 0x80080000,
}

block_lengths_med175 = {
    1: 0x00BF00,  # boot 0x04000..0x0FEFF (SGO container span)
    2: 0x020000,
    3: 0x040000,
    4: 0x0F8000,
}

med175_binfile_offsets = {
    1: 0x004000,
    2: 0x020000,
    3: 0x040000,
    4: 0x080000,
}

med175_binfile_size = 0x178000  # 1.5 MB TC1766 read (0x0..0x178000)

med175_project_name = "MED175"

med175_crypto = PlaintextCrypto()

med175_control_module_identifier = ControlModuleIdentifier(0x7E8, 0x7E0)

checksum_block_location_med175 = {
    1: 0x80004030, 2: 0x80020030, 3: 0x80040030, 4: 0x80080030,
}

# --- Flash-procedure placeholders (UDS specifics NOT yet reverse-engineered) ---
block_identifiers_med175 = {n: n for n in range(1, 5)}
block_checksums_med175 = {n: bytes.fromhex("00000000") for n in range(1, 5)}
software_version_location_med175 = {n: [0, 0] for n in range(1, 5)}
box_code_location_med175 = {n: [0, 0] for n in range(1, 5)}
block_transfer_sizes_med175 = {n: 0x0FFE for n in range(1, 5)}
block_name_to_int_med175 = {
    "BLK_04000": 1, "BLK_20000": 2, "CAL": 3, "ASW": 4,
}

med175_flash_info = FlashInfo(
    base_addresses_med175,
    block_lengths_med175,
    sa2_script_med175,
    block_names_frf_med175,
    block_identifiers_med175,
    block_checksums_med175,
    med175_control_module_identifier,
    software_version_location_med175,
    box_code_location_med175,
    block_transfer_sizes_med175,
    med175_binfile_offsets,
    med175_binfile_size,
    med175_project_name,
    med175_crypto,
    block_name_to_int_med175,
    None,  # patch_info: no CBOOT/RSA patch (Gen1 MEDC17 has no signature)
    checksum_block_location_med175,
)
