from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto.vl300 import VL300

# VL300 (01J) — Audi multitronic CVT (A4 8E/B7, A6 4F, A8 4E), Temic, Infineon
# C167. Firmware identifies itself as "VL300 Standard C167" / "V30 01J ...".
# SW part numbers 8E?/4E?/4F? 910155/157/159 (+ some 910156, e.g. 8E4910156L,
# 4F5910156S; most other x910156 are Bosch engine SGOs, NOT VL300).
#
# Container: "SGML Object File" (.sgo), same layout as the pre-MQB DQ250 SGO
# (see lib/containers/dsg_premqb_sgo.py). One flash block, btype 0x01, 0x008000..0x07FFFF,
# uncompressed, encrypted with the VL300 cipher (lib/crypto/vl300.py):
#     p[i] = T[(c[i] + c[i-1]) & 0xFF],  IV c[-1] = 0xFF
# Two table generations T1/T2 (data/vl300_sgo_T{1,2}.bin), auto-selected by
# lib/containers/vl300_sgo.py. The block header carries a 16-bit checksum at +0x13
# (algorithm unknown: not sum8/sum16/common CRC16 over plain- or ciphertext).
#
# Flat image layout (0x80000 total):
#   0x000000-0x008000  bootloader (fixed, not in SGO)
#   0x008000-0x080000  ASW+CAL   (block 1, 0x78000)
# Box code (11 chars, space padded) at 0x20000, SW version (4 chars) at 0x1FFFC.
# OLS "VAG Temic VL300 - Original.ols" offsets = image offset - 0x8000.
#
# Unpack/metadata only: the pre-UDS (KWP2000-era) flash protocol is not
# implemented, so there is no VW_Flash.py CLI flag for this module.

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

block_identifiers_dsg = {1: 0x01}

block_transfer_sizes_dsg = {1: 0x800}

software_version_location_dsg = {1: [0x1FFFC - 0x8000, 0x20000 - 0x8000]}

box_code_location_dsg = {1: [0x20000 - 0x8000, 0x2000B - 0x8000]}

block_checksums_dsg = {1: bytes.fromhex("FFFFFFFF")}

block_lengths_dsg = {1: 0x78000}

# SA2 seed/key bytecode, identical in all 53 VL300 SGOs (Temic family; same
# script as DL382 0CK except the final EOR constant 0x03F780FC).
dsg_sa2_script = bytes.fromhex(
    "6802814993A55A55AA4A05878105952668058249845AA5AA558703F780FC4C"
)

block_names_frf_dsg = {1: "SW"}

dsg_binfile_offsets = {1: 0x8000}

dsg_binfile_size = 0x80000

dsg_project_name = "VL300"

dsg_crypto = VL300("1")  # T2 for A6 4F generation; lib/containers/vl300_sgo.py auto-selects

block_name_to_int = {"SW": 1}

dsg_flash_info = FlashInfo(
    None,
    block_lengths_dsg,
    dsg_sa2_script,
    block_names_frf_dsg,
    block_identifiers_dsg,
    block_checksums_dsg,
    dsg_control_module_identifier,
    software_version_location_dsg,
    box_code_location_dsg,
    block_transfer_sizes_dsg,
    dsg_binfile_offsets,
    dsg_binfile_size,
    dsg_project_name,
    dsg_crypto,
    block_name_to_int,
    None,
    None,
)
