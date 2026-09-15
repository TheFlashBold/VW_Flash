"""
Bosch EDC17C64 (VAG EA288 2.0 TDI, e.g. 04L906021*) flash info.

This module targets the *newer* ASAM ODX-F (XML) FRF containers whose blocks use
<ENCRYPT-COMPRESS-METHOD> = "A1": compression 'A' = LZSS10, encryption '1' =
repeating-XOR with key "BiWbBuD101" (see lib/crypto/edc17.py). This is a
different codec from the older bracket-text "BCB Type1" EDC17 (extract_frf_edc17.py).

Scope: READ / EXTRACTION only. extract_odx() uses only flash_info.crypto plus the
block sizes/compression carried in the ODX itself, so extraction is fully
supported. Flashing is NOT implemented -- there is no verified SA2 script, no UDS
block checksums and no CBOOT patch here; those fields are placeholders.

Block layout (self-derived from each decoded block's 32-byte descriptor, whose
bytes[12:16] LE are the block END address at base 0x80000000). The 5 blocks tile
a 4 MB image; the ~64 KB gap at 0x0FF00-0x20000 is a non-flashable boot/RSA region
not carried in the FRF.
"""
from lib.constants import (
    FlashInfo,
    ControlModuleIdentifier,
)
from lib.crypto import edc17

# ODX FLASHDATA order 1..5 == FD_01..FD_05 (older single-digit variants FD_0..FD_4
# extract identically; extract_odx keys output by the ODX SHORT-NAME, not by these).
block_names_frf_edc17c64 = {
    1: "FD_01",  # small boot-adjacent block (0xBF00)
    2: "FD_02",  # ASW  (0x260000)
    3: "FD_03",  # CAL  (0x80000)
    4: "FD_04",  # small block (0x4000)
    5: "FD_05",  # data (0xFCF00)
}

# Block start addresses (TC1793, base 0x80000000), from the block descriptors.
base_addresses_edc17c64 = {
    1: 0x80004000,
    2: 0x80020000,  # ASW
    3: 0x80380000,  # CAL
    4: 0x80000000,
    5: 0x80283000,
}

block_lengths_edc17c64 = {
    1: 0x00BF00,
    2: 0x260000,
    3: 0x080000,
    4: 0x004000,
    5: 0x0FCF00,
}

# File offsets in the assembled 4 MB flat bin (== base - 0x80000000).
edc17c64_binfile_offsets = {
    1: 0x004000,
    2: 0x020000,
    3: 0x380000,
    4: 0x000000,
    5: 0x283000,
}

edc17c64_binfile_size = 0x400000  # 4 MB

edc17c64_crypto = edc17.Edc17RepeatingXor()

edc17c64_control_module_identifier = ControlModuleIdentifier(0x7E8, 0x7E0)

# --- Extraction-only placeholders (not used by extract_odx) ---
block_identifiers_edc17c64 = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5}
block_checksums_edc17c64 = {n: bytes.fromhex("00000000") for n in range(1, 6)}
software_version_location_edc17c64 = {n: [0, 0] for n in range(1, 6)}
box_code_location_edc17c64 = {n: [0, 0] for n in range(1, 6)}
block_transfer_sizes_edc17c64 = {n: 0xFFD for n in range(1, 6)}
checksum_block_location_edc17c64 = {n: 0x0 for n in range(0, 6)}
block_name_to_int_edc17c64 = {
    "FD_01": 1, "ASW": 2, "FD_02": 2, "CAL": 3, "FD_03": 3,
    "FD_04": 4, "FD_05": 5,
}

edc17c64_flash_info = FlashInfo(
    base_addresses_edc17c64,
    block_lengths_edc17c64,
    None,  # sa2_script: flashing not supported
    block_names_frf_edc17c64,
    block_identifiers_edc17c64,
    block_checksums_edc17c64,
    edc17c64_control_module_identifier,
    software_version_location_edc17c64,
    box_code_location_edc17c64,
    block_transfer_sizes_edc17c64,
    edc17c64_binfile_offsets,
    edc17c64_binfile_size,
    "EDC17C64",
    edc17c64_crypto,
    block_name_to_int_edc17c64,
    None,  # patch_info: no CBOOT patch
    checksum_block_location_edc17c64,
)
