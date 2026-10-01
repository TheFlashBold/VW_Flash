from lib.constants import FlashInfo
from lib.modules import al551

# AL450 (2H0927158*) — ZF 8HP TCU in the VW Amarok V6 TDI ("ITCU2", 8HPXY,
# SH-2A big-endian, EV_TCMAL450211). Version string "ZH?X5???xxxx" in the CAL.
#
# Same container, codec and flash layout as AL551 (see lib/modules/al551.py):
# ENCRYPT-COMPRESS-METHOD "22" = ZF LZSS 5/11 + XOR "CyA2008ZFVAGtcuxsam",
# blocks FD_1..FD_4 with identical 0x876543xx headers. Verified on
# 2H0927158A/B/E/H/J: FD_4 of J_1004 matches a J_0003 OBD CAL read 99.6% at
# offset 0, and ASW self-pointers land on SH-2A function prologues only at
# 0x40000 (10.9% vs <1% when shifted).
#   0x006000-0x007E00  FD_2  (id 02, 0x01E00)
#   0x020000-0x03FE00  FD_3  (id 03, 0x1FE00)
#   0x040000-0x17FE00  FD_1  ASW/program (id 01, 0x13FE00)
#   0x180200-0x200000  FD_4  CAL (id 04, 0x7FE00; ZFADINFO, box code + version)

dsg_control_module_identifier = al551.dsg_control_module_identifier
block_identifiers_dsg = al551.block_identifiers_dsg
block_transfer_sizes_dsg = al551.block_transfer_sizes_dsg
software_version_location_dsg = al551.software_version_location_dsg
box_code_location_dsg = al551.box_code_location_dsg
block_checksums_dsg = al551.block_checksums_dsg
block_lengths_dsg = al551.block_lengths_dsg
dsg_sa2_script = al551.dsg_sa2_script
block_names_frf_dsg = al551.block_names_frf_dsg
dsg_binfile_offsets = al551.dsg_binfile_offsets
dsg_binfile_size = al551.dsg_binfile_size
dsg_crypto = al551.dsg_crypto
block_name_to_int = al551.block_name_to_int

dsg_project_name = "AL450"

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

# same block CRCs as AL551
dsg_flash_info.checksum_image = al551.checksum_image
dsg_flash_info.checksum_fix_image = al551.checksum_fix_image
