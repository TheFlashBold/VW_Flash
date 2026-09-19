from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import dsg

# DL501 (0B5) — Audi longitudinal 7-speed S tronic ("DL501 Gen2"), TriCore TC1766.
# Applications: 4G5927156* (A6/A7 C7), 8K5927156* (A4/A5 B8), etc.
#
# FRF container is the classic embedded ODX (not ODX-F). Flash blocks use
# ENCRYPT-COMPRESS-METHOD "11": encrypted with the DSG progressive substitution
# cipher (same algorithm as DQ250/DQ400, rolling increment 0x167) then
# LZSS10-compressed.
#
# The 256-byte substitution table is DL501-specific. It lives in the immutable
# bootloader region (not in the reflashable ASW/CAL blocks); it was recovered by
# scanning a full 4G5927156 flat bin for a 256-byte permutation window and
# confirmed by clean LZSS10 decompression of both blocks (FD_2/FD_4) to their
# declared UNCOMPRESSED-SIZE, yielding the expected DL501 strings
# ("EV_TCMDL501", "DL501 Tricore 1766", "0B5927156K", box code "4G5927156").
# Table stored at data/dl501_key.bin.
#
# Flat image layout (0x2A0000 total), derived by anchor-match localisation of the
# decompressed blocks against a full flat bin (FD_4 votes base 0x40000 with 278/1128
# anchors; FD_2 clusters at ~0x20000 — the ~0x1a0 spread is version shift between the
# v0003 reference bin and the v0004 blocks). CAL sits immediately before ASW; the two
# are contiguous (0x20000 + 0x140000 = 0x160000 spanning 0x20000-0x180000):
#   0x000000-0x020000  bootloader / CBOOT (fixed, not in FRF); holds the sub table @0x10d9c
#   0x020000-0x040000  CAL   (block id 0x02 / FD_2, 0x020000)
#   0x040000-0x180000  ASW   (block id 0x01 / FD_4, 0x140000)
#   0x180000-0x2A0000  separate data region (fixed, not in FRF; ~0x10000 real @0x280000)

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

# Block ints: 1 = ASW, 2 = CAL. ODX SOURCE-START-ADDRESS is the block identifier
# (0x01 for ASW, 0x02 for CAL); shortname_to_block keys on it.
block_identifiers_dsg = {1: 0x01, 2: 0x02}

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800}

software_version_location_dsg = {
    1: [0x0, 0x0],
    2: [0x0, 0x0],
}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0]}

block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    1: 0x140000,  # ASW (1310720 bytes)
    2: 0x20000,   # CAL (131072 bytes)
}

# Placeholder — DL501 seed/key SA2 bytecode not required for FRF unpacking.
dsg_sa2_script = bytes.fromhex("00")

block_names_frf_dsg = {1: "FD_4", 2: "FD_2"}

dsg_binfile_offsets = {
    1: 0x40000,  # ASW
    2: 0x20000,  # CAL
}

dsg_binfile_size = 0x2A0000  # 2752512

dsg_project_name = "DL501"

dsg_crypto = dsg.DSG("dl501_key.bin")

# Conversion dict for block name to number
block_name_to_int = {"ASW": 1, "CAL": 2}

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
