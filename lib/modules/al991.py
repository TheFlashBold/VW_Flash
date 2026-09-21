from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import dq500

# AL991 (0C8) — ZF 8HP transmission control unit with an on-board signal DSP
# (blocks contain "DSP developed by Ulrich Stegmann" / "DSP Calibration MAP" /
# "Copyright by Volkswagen AG"). Spare part 0C8927750* (e.g. A8 D4). EV_TCMAL991.
#
# Container: classic embedded ODX. Both flashdata blocks are stored with
# ENCRYPT-COMPRESS-METHOD "00" — i.e. PLAINTEXT: no compression, no encryption
# (raw DATA length == UNCOMPRESSED-SIZE). So no crypto/table is needed; the block
# bytes are the flash content verbatim. Crypto is therefore a passthrough (DQ500).
#
# Two blocks (SOURCE-START-ADDRESS 01/02):
#   SSA 01 (FD_0DATA) 0x100000  — main program flash
#   SSA 02 (FD_1DATA) 0x3B000   — DSP calibration/code
# The ODX carries only the block ids, not target addresses, and no full AL991
# reference bin is available, so the two blocks are laid out contiguously in SSA
# order (01 @ 0x0, 02 @ 0x100000). This is a faithful concatenation of the
# plaintext blocks, not a verified flash memory map — treat the 0x100000 boundary
# as the block split.

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

block_identifiers_dsg = {1: 0x01, 2: 0x02}

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800}

software_version_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0]}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0]}

block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    1: 0x100000,  # main program (1048576 bytes)
    2: 0x3B000,   # DSP calibration (241664 bytes)
}

dsg_sa2_script = bytes.fromhex("00")

block_names_frf_dsg = {1: "FD_0DATA", 2: "FD_1DATA"}

dsg_binfile_offsets = {
    1: 0x0,        # main program
    2: 0x100000,   # DSP cal, contiguous after block 1
}

dsg_binfile_size = 0x13B000  # 1290240

dsg_project_name = "AL991"

# Plaintext blocks -> passthrough "crypto".
dsg_crypto = dq500.DQ500()

block_name_to_int = {"PROG": 1, "DSP": 2}

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
