import zlib

from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import plaintext

try:
    from sa2_seed_key.sa2_seed_key import Sa2SeedKey
except ImportError:  # allow importing the module for checksum/extract without the VM
    Sa2SeedKey = None

# MQB electric power steering (gateway diagnostic address 0x44, UDS 0x7E8/0x712),
# ZF "BAS Gen1 MQB37" — 3Q0909144* / 5Q0909144* (also 2Q1909144* on the A0
# platform, but that one is TRW, not this ZF part). Renesas V850 core.
# ODX ECU variant EV_SteerAssisMQB.
#
# Container: classic VW FRF, standard FRF key (lib/extract_flash.open_frf_zip).
# Each FRF carries ONE block as a single-session ODX with
# ENCRYPT-COMPRESS-METHOD "00" => plaintext, no compression (PlaintextCrypto).
#
# Three blocks, keyed here by their ODX SOURCE-START-ADDRESS:
#   id 0x02  H7  bootloader  @0x00000  24 KB   ("MQB_BB_xx_01", "BOOT----...ZF0000")
#   id 0x07  H1  application @0x07000  ~452 KB (SW id "3E0_400_D_xx_xx" @0x46,
#                                               assist curves + CAL)
#   id 0x06  H2  co-block    @0x78000  52 KB   ("V850T05", "MQB_BB_xx_01")
#
# Flash protection (proven against every H1/H2/H7 FRF, 2026-10):
#   * SA2 seed/key  -> eps_sa2_script below (identical across all versions/blocks)
#   * ALFID 01 41 01
#   * CRC32         -> keyless, standard reflected CRC-32 (zlib.crc32) over the
#                     WHOLE block. The value is NOT stored inside the block; it
#                     lives in the ODX <FW-CHECKSUM> and is what the ECU verifies
#                     after download. There is NO RSA signature anywhere.
# So to re-release a patched H1: recompute block_crc32(block) and write it as the
# ODX FW-CHECKSUM (big-endian hex); authenticate with seed_key() during 0x27.

# Diagnostic (ISO-TP) CAN IDs for gateway address 0x44. txid = tester->ECU request,
# rxid = ECU->tester response. Best-known MQB EPS pair; VERIFY on the actual car
# (the gateway assigns these) and override with --txid/--rxid if needed.
eps_control_module_identifier = ControlModuleIdentifier(0x77C, 0x712)

# SA2 bytecode (ODX <SECURITY-METHOD>SA2 <FW-SIGNATURE>). Disassembly:
#   FOR 5
#     EOR 0x003F1735
#     ADD 0xA3FF7890
#     BCC +1        (if no carry, skip the next instruction)
#     RSR
#   NEXT
#   END
eps_sa2_script = bytes.fromhex("680587003F173593A3FF78904A0182494C")

# int (our block number = ODX SOURCE-START-ADDRESS) -> ODX block identifier
block_identifiers_eps = {2: 0x02, 6: 0x06, 7: 0x07}

# Logical load addresses in the ECU memory map.
base_addresses_eps = {2: 0x00000, 7: 0x07000, 6: 0x78000}

# Nominal block lengths (bytes). H1 size varies a little by SW version; the real
# length comes from the FRF, these are for reference / binfile layout only.
block_lengths_eps = {2: 0x06000, 7: 0x71000, 6: 0x0D000}

# The bootloader's RequestDownload reports maxNumberOfBlockLength = 0x82, so each
# TransferData may carry at most 0x80 data bytes (the firmware rejects more with NRC
# 0x71). Keep transfers at 0x80.
block_transfer_sizes_eps = {2: 0x80, 6: 0x80, 7: 0x80}

# SW id "3E0_400_D_xx_xx" sits at 0x46 in H1; box code is the ZF part number.
software_version_location_eps = {2: [0x0, 0x0], 6: [0x0, 0x0], 7: [0x46, 0x55]}
box_code_location_eps = {2: [0x0, 0x0], 6: [0x0, 0x0], 7: [0x0, 0x0]}

# No stored in-block CRC (checksum is external, in the ODX). Placeholder.
block_checksums_eps = {
    2: bytes.fromhex("FFFFFFFF"),
    6: bytes.fromhex("FFFFFFFF"),
    7: bytes.fromhex("FFFFFFFF"),
}

block_names_frf_eps = {2: "H7", 6: "H2", 7: "H1"}

# Blocks live in the ECU at their base addresses; a flat image would be ~0x85000.
eps_binfile_offsets = {2: 0x00000, 7: 0x07000, 6: 0x78000}
eps_binfile_size = 0x85000

eps_project_name = "EPS_MQB"

eps_crypto = plaintext.PlaintextCrypto()

# Human names -> block number. H1 is the application/CAL block.
block_name_to_int = {"BOOT": 2, "H7": 2, "H2": 6, "ASW": 7, "H1": 7, "CAL": 7}

eps_flash_info = FlashInfo(
    base_addresses_eps,
    block_lengths_eps,
    eps_sa2_script,
    block_names_frf_eps,
    block_identifiers_eps,
    block_checksums_eps,
    eps_control_module_identifier,
    software_version_location_eps,
    box_code_location_eps,
    block_transfer_sizes_eps,
    eps_binfile_offsets,
    eps_binfile_size,
    eps_project_name,
    eps_crypto,
    block_name_to_int,
    None,
    None,
)


def seed_key(seed: bytes) -> bytes:
    """Run the EPS SA2 script on a 4-byte big-endian seed, return the 4-byte key.

    Used for UDS SecurityAccess level 0x11/0x12 (programming) on module 0x44.
    """
    if Sa2SeedKey is None:
        raise RuntimeError("sa2_seed_key package not available")
    if len(seed) != 4:
        raise ValueError(f"EPS seed must be 4 bytes, got {len(seed)}")
    vm = Sa2SeedKey(bytearray(eps_sa2_script), int.from_bytes(seed, "big"))
    key = vm.execute()
    if isinstance(key, int):
        return key.to_bytes(4, "big")
    return bytes(key)


def block_crc32(block: bytes) -> int:
    """Keyless CRC-32 the ECU verifies after flashing a block (reflected CRC-32,
    poly 0x04C11DB7, init/xorout per zlib). Computed over the whole block."""
    return zlib.crc32(block) & 0xFFFFFFFF


def fw_checksum_hex(block: bytes) -> str:
    """CRC-32 formatted as the ODX <FW-CHECKSUM> big-endian hex string.

    After patching a block, write this value into the block's ODX so the ECU's
    post-download verify passes."""
    return f"{block_crc32(block):08X}"


# NB: no checksum_image / checksum_fix_image hooks. The EPS CRC is keyless but is
# stored in the ODX <FW-CHECKSUM>, not inside the block, so the in-image checksum
# framework (VW_Flash.py --action checksum/prepare) does not apply. The patch
# workflow uses the library helpers below directly:
#   crc  = eps_flash_info.block_crc32(patched_block)
#   hexv = eps_flash_info.fw_checksum_hex(patched_block)   # -> ODX FW-CHECKSUM
#   key  = eps_flash_info.seed_key(seed_from_0x27)
eps_flash_info.seed_key = seed_key
eps_flash_info.block_crc32 = block_crc32
eps_flash_info.fw_checksum_hex = fw_checksum_hex
