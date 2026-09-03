from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import aes

# DQ500-0DL (RS3/TTRS/RSQ3) DSG transmission ECU
# AES-128-CBC encryption, LZSS10 compression (method=AA)
# 3 blocks: CBOOT (1), ASW (2), CAL (3)
# Key/IV found at CBOOT offsets 0x550/0x540 in bench dump

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800, 3: 0x800}

software_version_location_dsg = {
    1: [0x0, 0x0],
    2: [0x0, 0x0],
    3: [0xFE21, 0xFE2B],  # "0DL300013L" in CAL block
}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0], 3: [0x0, 0x0]}

block_identifiers_dsg = {1: 1, 2: 2, 3: 3}

block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
    3: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    1: 0x1FE00,   # CBOOT/DRIVER (130560 bytes)
    2: 0x10FE00,  # ASW (1113600 bytes)
    3: 0x3FE00,   # CAL (261632 bytes)
}

sa2_script_dsg = bytes.fromhex(
    "6806814A05876B5F7DD5494C"
)

block_names_frf_dsg = {1: "FD_01DATA", 2: "FD_02DATA", 3: "FD_03DATA"}

dsg_binfile_offsets = {
    1: 0x10200,   # CBOOT/DRIVER
    2: 0x30200,   # ASW
    3: 0x140200,  # CAL
}

dsg_binfile_size = 1572864  # 0x180000

dsg_project_name = "ST3A"

dq500_0dl_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
dq500_0dl_iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
dsg_crypto = aes.AES(dq500_0dl_key, dq500_0dl_iv)

block_name_to_int = {"CBOOT": 1, "ASW": 2, "CAL": 3}

dsg_flash_info = FlashInfo(
    None,
    block_lengths_dsg,
    sa2_script_dsg,
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

# Same SH-2A CBOOT as DQ381 — 2-phase erase requires retries
dsg_flash_info.erase_retries = 5
