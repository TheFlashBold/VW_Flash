from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import dq400

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

block_transfer_sizes_dsg = {2: 0x4B0, 3: 0x800, 4: 0x800}

software_version_location_dsg = {
    2: [0x0, 0x0],
    3: [0x0, 0x0],
    4: [0x3FFA0, 0x3FFB4],
}

box_code_location_dsg = {2: [0x0, 0x0], 3: [0x0, 0x0], 4: [0x0, 0x0]}

block_identifiers_dsg = {2: 0x30, 3: 0x50, 4: 0x51}

block_checksums_dsg = {
    2: bytes.fromhex("FFFFFFFF"),
    3: bytes.fromhex("FFFFFFFF"),
    4: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    2: 0xC00,  # DRIVER (3072 bytes)
    3: 0x116ABD,  # ASW (1141437 bytes) - 0DD300040_1602; was 0x107651 (older SW)
    4: 0x40000,  # CAL (262144 bytes)
}

dsg_sa2_script = bytes.fromhex(
    "68028149680593A55A55AA4A0587810595268249845AA5AA558703F780574C"
)
block_names_frf_dsg = {2: "FD_2", 3: "FD_3", 4: "FD_4"}

# Flash base is 0x80000000 (TriCore internal flash, 2.5 MB).
# Layout verified against a DQ400e bench full backup (int_flash.bin, 0DD300045H):
#   0x00000000-0x00040000  boot/CBOOT (protected, not in FRF)
#   0x00040000-0x00080000  CAL   (block 0x51) -- FD_4 content matches byte-exact @0x40000
#   0x00080000-...         ASW   (block 0x50) -- dense code region @0x80000
# DRIVER (block 0x30) is a RAM-loaded flash driver (full of 0xd4xxxx DSPR refs),
# not persistent flash; kept at 0x0 only so the binfile round-trips.
dsg_binfile_offsets = {
    2: 0x0,       # DRIVER  - RAM flash driver, not stored in main flash
    3: 0x80000,   # ASW     @ flash 0x80080000
    4: 0x40000,   # CAL     @ flash 0x80040000
}

dsg_binfile_size = 0x280000  # 2.5 MB internal flash (base 0x80000000)

dsg_project_name = "F"

dsg_crypto = dq400.DQ400()

# Conversion dict for block name to number
block_name_to_int = {"DRIVER": 2, "ASW": 3, "CAL": 4}

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
