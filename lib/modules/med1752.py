"""
Bosch MED17.5.2 (VAG petrol, TC1767, all-internal 2 MB flash; e.g. part
1037520682, box code family "ME(D)/EDC17 B_CB.02.03.00") flash info.

MED17.5.2 is the ODD ONE OUT in the MED17.5 family:
  * SA2 seed/key is a DIFFERENT script (FOR 10, SUB/XOR/XOR/ADD) than the common
    variant shared by MED17.5 / 17.5.1 / 17.5.5 (see med175.py). It is the fully
    firmware-harness-validated one.
  * Block layout is the TC1767 all-internal layout (ASW 0x80020000..0x801BFFFB,
    CAL 0x801C0000..0x801FFFFB).

The CRC scheme is IDENTICAL across the whole family, so this module reuses the
verified primitives from med175 (crc32_med175 / crc_ok_med175 /
crc_fix_word_med175, init 0xFADECAFE -> residue 0xCAFEAFFE).

Blocks are PLAINTEXT (no AES/RSA). All ranges verified against the stock
1037520682 image: crc32_med175(range, 0xFADECAFE) == 0xCAFEAFFE.
"""
from lib.constants import (
    FlashInfo,
    ControlModuleIdentifier,
)
from lib.crypto.plaintext import PlaintextCrypto

# Reuse the family-universal, firmware-verified CRC scheme.
from lib.modules.med175 import (
    sa2_key,
    crc32_med175,
    crc_ok_med175,
    crc_fix_word_med175,
    MED175_CRC_INIT,
    MED175_CRC_RESIDUE,
)

# --- SA2 (MED17.5.2-specific; TRIPLE-VALIDATED incl. the firmware VM in QEMU) ---
# Script @ flash 0x8000EE5A, run by the on-ECU VAG SA2 bytecode VM FUN_800085ba.
#   68 0A         FOR 10
#   84 AF45D107   SUB 0xAF45D107  (carry = borrow)
#   4A 03         BCC +3
#   81            RSL (rotate-left-1, carry = old MSB)
#   6B 06         BRA +6
#   82            RSR (rotate-right-1, carry = old LSB)
#   87 02C11DB7   XOR 0x02C11DB7
#   81            RSL
#   4A 08         BCC +8
#   87 562C11DB   XOR 0x562C11DB
#   82            RSR
#   6B 05         BRA +5
#   93 B5A4200F   ADD 0xB5A4200F
#   49            NEXT
#   4C            END
# Firmware-accepted: 0x12345678->0xEAAB0431, 0xFFFFFFFF->0x0141730B,
#                    0x00000001->0x301724B9, 0xDEADBEEF->0x7C56D459.
# NOTE: dspl1236/VAGFlasher's Feistel (const 0x1A76B3C4) is FABRICATED and wrong.
sa2_script_med1752 = bytes.fromhex(
    "680A84AF45D107" "4A03" "81" "6B06" "82" "8702C11DB7" "81" "4A08"
    "87562C11DB" "82" "6B05" "93B5A4200F" "49" "4C"
)


def sa2_key_med1752(seed: int) -> int:
    """MED17.5.2 SA2 seed -> key, the exact decoded control flow of FUN_800085ba.

    Script decodes to: FOR 10 { SUB 0xAF45D107 (carry=borrow);
    if borrow: ROL else: ROR, XOR 0x02C11DB7; ROL; if carry: XOR 0x562C11DB, ROR
    else: ADD 0xB5A4200F }.
    """
    return sa2_key(sa2_script_med1752, seed)


# --- Block layout (TC1767, from the FECADEFA descriptors; residue-verified) ---
# base : (end, correction_word@+0x30)
med1752_block_descriptors = {
    0x80000000: (0x80003FFB, 0x6F2FE097),  # reset vectors / header  (boot-reserved)
    0x80004000: (0x8000FCFF, 0xD0C9FC04),  # bootblock / flash loader (boot-reserved)
    0x80010000: (0x80013FFB, 0x3C901AC9),
    0x80014000: (0x80017EFB, 0xF8F3C728),
    0x80018000: (0x8001FEFB, 0x370A29B3),
    0x8001FF00: (0x8001FFDF, None),
    0x80020000: (0x801BFFFB, 0x2BBF3D2D),  # ASW
    0x801C0000: (0x801FFFFB, 0x1AC0B992),  # CAL
}

# CRC-checked ranges (inclusive [start, end]) -- all verified residue 0xCAFEAFFE.
med1752_crc_ranges = {
    "vectors":   (0x80000000, 0x80003FFB),
    "bootblock": (0x80004000, 0x8000FCFF),
    "blk10000":  (0x80010000, 0x80013FFB),
    "blk14000":  (0x80014000, 0x80017EFB),
    "blk18000":  (0x80018000, 0x8001FEFB),
    "blk18ff00": (0x8001FF00, 0x8001FFDF),
    "ASW":       (0x80020000, 0x801BFFFB),
    "CAL":       (0x801C0000, 0x801FFFFB),
}

# OBD-flashable set: boot region (0x80000000..0x8000FFFF) is loader-reserved; the
# application blocks below are written over OBD.
block_names_frf_med1752 = {
    1: "BLK_10000",
    2: "BLK_14000",
    3: "BLK_18000",
    4: "ASW",
    5: "CAL",
}

base_addresses_med1752 = {
    1: 0x80010000,
    2: 0x80014000,
    3: 0x80018000,
    4: 0x80020000,  # ASW
    5: 0x801C0000,  # CAL
}

block_lengths_med1752 = {
    1: 0x004000,  # 0x80010000..0x80013FFB
    2: 0x003F00,  # 0x80014000..0x80017EFB
    3: 0x007F00,  # 0x80018000..0x8001FEFB
    4: 0x1A0000,  # ASW 0x80020000..0x801BFFFB
    5: 0x040000,  # CAL 0x801C0000..0x801FFFFB
}

med1752_binfile_offsets = {
    1: 0x010000,
    2: 0x014000,
    3: 0x018000,
    4: 0x020000,
    5: 0x1C0000,
}

med1752_binfile_size = 0x200000  # 2 MB, all internal (TC1767)

med1752_project_name = "MED1752"

med1752_crypto = PlaintextCrypto()

med1752_control_module_identifier = ControlModuleIdentifier(0x7E8, 0x7E0)

# Checksum locations = block_start+0x30 (residue-correction word, not a stored CRC).
checksum_block_location_med1752 = {
    1: 0x80010030, 2: 0x80014030, 3: 0x80018030,
    4: 0x80020030,  # ASW
    5: 0x801C0030,  # CAL
}
block_checksums_med1752 = {
    1: bytes.fromhex("3C901AC9"),
    2: bytes.fromhex("F8F3C728"),
    3: bytes.fromhex("370A29B3"),
    4: bytes.fromhex("2BBF3D2D"),  # ASW
    5: bytes.fromhex("1AC0B992"),  # CAL
}

# --- Flash-procedure placeholders (UDS specifics NOT yet reverse-engineered) ---
block_identifiers_med1752 = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}
software_version_location_med1752 = {n: [0, 0] for n in (1, 2, 3, 4, 5)}
box_code_location_med1752 = {n: [0, 0] for n in (1, 2, 3, 4, 5)}
block_transfer_sizes_med1752 = {n: 0x0FFE for n in (1, 2, 3, 4, 5)}
block_name_to_int_med1752 = {
    "BLK_10000": 1, "BLK_14000": 2, "BLK_18000": 3, "ASW": 4, "CAL": 5,
}

med1752_flash_info = FlashInfo(
    base_addresses_med1752,
    block_lengths_med1752,
    sa2_script_med1752,
    block_names_frf_med1752,
    block_identifiers_med1752,
    block_checksums_med1752,
    med1752_control_module_identifier,
    software_version_location_med1752,
    box_code_location_med1752,
    block_transfer_sizes_med1752,
    med1752_binfile_offsets,
    med1752_binfile_size,
    med1752_project_name,
    med1752_crypto,
    block_name_to_int_med1752,
    None,  # patch_info: no CBOOT/RSA patch (Gen1 MEDC17 has no signature)
    checksum_block_location_med1752,
)
