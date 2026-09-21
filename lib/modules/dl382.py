from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import dsg

# DL382 (0CK) — Audi longitudinal 7-speed S tronic DSG, TriCore (TC174x; firmware
# "DL382 Tricore 1746"). Successor to DL501 on the B9/newer platform. Box code
# 0CK910255* / spare-part 8W0/8W1/8W2 927155*. NB the firmware also carries the
# "EV_TCMVL381" string — DL382 shares a codebase lineage with VL381/DL501.
#
# Container: newer embedded ODX (DB_0xDATA / DB_0xERASEDATA naming) with FOUR
# flashdata blocks (SOURCE-START-ADDRESS 01-04). Blocks use ENCRYPT-COMPRESS-
# METHOD "11" = DSG progressive substitution cipher (rolling inc 0x167) + LZSS10.
#
# Crypto: DL382 uses the SAME 256-byte substitution table as DL501 (verified: the
# DL501 table decrypts all four blocks cleanly to their exact uncompressed sizes,
# and the identical table is present in the DL382 bootloader @0x3bdd0). So this
# module reuses data/dl501_key.bin.
#
# Flat image layout (0x280000 total), file offset = CPU addr - 0x80000000:
#   0x000000-0x020000  SBOOT (vector table 1d000002..., fixed, not in FRF)
#   0x020000-0x040000  FD_04 (block id 0x04, 0x20000)          [provisional]
#   0x040000-0x080000  FD_03 (block id 0x03, 0x8000) + reserved [provisional]
#   0x080000-0x0c0000  FD_02 (block id 0x02, 0x40000)   -- CONFIRMED byte-exact
#   0x0c0000-0x280000  FD_01 (block id 0x01, 0x1c0000)  -- ASW+CAL, CONFIRMED
# FD_01/FD_02 offsets are certain: FD_02's decrypted head matches a full flat bin
# at 0x80000 byte-for-byte; FD_01's reset-vector header (1d01xxxx0090a5a5) matches
# at 0xc0000, and the A2L (DL382_FL_0CK910255A P008) places all code (0x8008xxxx)
# and CAL (0x8024/0x8025xxxx) inside file 0x80000-0x280000 = FD_02+FD_01. FD_03/
# FD_04 hold no A2L calibration; their exact offsets are provisional (the only
# available full bin is a different variant, 8W2927155BA, whose 0x40000-0x80000
# is erased) but they sit in the 0x0-0x80000 boot half.

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

# Block ints follow the SSA number. 1=FD_01(ASW+CAL), 2=FD_02, 3=FD_03, 4=FD_04.
block_identifiers_dsg = {1: 0x01, 2: 0x02, 3: 0x03, 4: 0x04}

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800, 3: 0x800, 4: 0x800}

software_version_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0], 3: [0x0, 0x0], 4: [0x0, 0x0]}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0], 3: [0x0, 0x0], 4: [0x0, 0x0]}

block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
    3: bytes.fromhex("FFFFFFFF"),
    4: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    1: 0x1C0000,  # FD_01 ASW+CAL (1835008 bytes)
    2: 0x40000,   # FD_02 (262144 bytes)
    3: 0x8000,    # FD_03 (32768 bytes)
    4: 0x20000,   # FD_04 (131072 bytes)
}

# Placeholder — DL382 seed/key SA2 bytecode not required for FRF unpacking.
dsg_sa2_script = bytes.fromhex("00")

block_names_frf_dsg = {1: "FD_01DATA", 2: "FD_02DATA", 3: "FD_03DATA", 4: "FD_04DATA"}

dsg_binfile_offsets = {
    1: 0xC0000,   # FD_01 ASW+CAL
    2: 0x80000,   # FD_02
    3: 0x40000,   # FD_03  (provisional)
    4: 0x20000,   # FD_04  (provisional)
}

dsg_binfile_size = 0x280000  # 2621440

dsg_project_name = "DL382"

# DL382 shares the DL501 substitution table.
dsg_crypto = dsg.DSG("dl501_key.bin")

block_name_to_int = {"ASW": 1, "FD_02": 2, "FD_03": 3, "CAL": 4}

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
