from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import dsg

# VL381 (0AW) — Audi longitudinal multitronic CVT, TriCore TC1766. Firmware
# identifies itself as "VL381" (EV_TCMVL381 / "VL381 Tricore 1766").
# Applications: 4G2/8K2/8W2 927155* (A6/A7 C7, A4/A5 B8, A4 B9), box "0AW...".
#
# Container/crypto are the same family as DL501: classic embedded ODX, flash
# blocks with ENCRYPT-COMPRESS-METHOD "11" = DSG progressive substitution cipher
# (rolling increment 0x167) then LZSS10, but with a VL381-SPECIFIC 256-byte table.
#
# The table normally lives in the immutable bootloader, which was NOT present in
# any available dump (only a partial ASW+CAL flat read, boot region zeroed).
# It was instead recovered by a known-plaintext attack on the substitution
# cipher: given the exact matching pair FL_8K2927155L_0007 (FRF ciphertext) and
# its decompressed flat bin, the VW_Flash native LZSS compressor reproduces the
# OEM compressed stream byte-for-byte, yielding exact (compressed-plaintext,
# ciphertext) pairs. Because the table is a permutation, knowing one entry pins
# the running offset at every position holding that value, and adjacent known
# offsets reveal the rolling-table entry there; this cascades to the full 256
# entries (see tools/recover_dsg_substitution_table.py). Verified: decrypt+
# decompress of both FRF blocks reproduces the reference bin exactly. Table
# stored at data/vl381_key.bin.
#
# Flat image layout (0x180000 total), same shape as DL501:
#   0x000000-0x020000  bootloader / CBOOT (fixed, not in FRF)
#   0x020000-0x040000  CAL   (block id 0x02 / FD_2, 0x020000)
#   0x040000-0x170000  ASW   (block id 0x01 / FD_4, 0x130000)
#   0x170000-0x180000  tail  (fixed, not in FRF)

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

# Block ints: 1 = ASW (SSA 0x01), 2 = CAL (SSA 0x02).
block_identifiers_dsg = {1: 0x01, 2: 0x02}

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800}

software_version_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0]}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0]}

block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
}

block_lengths_dsg = {
    1: 0x130000,  # ASW (1245184 bytes)
    2: 0x20000,   # CAL (131072 bytes)
}

# Placeholder — VL381 seed/key SA2 bytecode not required for FRF unpacking.
dsg_sa2_script = bytes.fromhex("00")

block_names_frf_dsg = {1: "FD_4", 2: "FD_2"}

dsg_binfile_offsets = {
    1: 0x40000,  # ASW
    2: 0x20000,  # CAL
}

dsg_binfile_size = 0x180000  # 1572864

dsg_project_name = "VL381"

dsg_crypto = dsg.DSG("vl381_key.bin")

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
