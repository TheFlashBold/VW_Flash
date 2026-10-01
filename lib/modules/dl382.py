from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import plaintext

# DL382 (0CK) — Continental/Temic 7-speed DSG mechatronic, **Renesas SH-2A big
# endian** (NOT TriCore — see note below). ECU self-identifies as
# "EV_TCMDL382021" (app string at file 0x3C8E0 / 0xE003A); the lone
# "EV_TCMVL381" string at 0x8908 is a shared-library leftover in the boot ROM.
# Sample used for RE: "00859 DL382_micro" = 0CK927156Q, D4b Serienversion B2.
#
# CPU/arch: Renesas SH-2A, big-endian, IAR-compiled. Flash base 0x80000000
# (P1 cached; the UDS bootloader addresses handlers via 0xA0000000 P2 uncached —
# same physical flash, file offset = addr & 0x00FFFFFF). The previous revision of
# this module described DL382 as "TriCore TC174x" and reused the DL501
# substitution cipher; that was wrong for this 0CK Conti/SH-2A unit. The block
# LENGTHS it carried were correct (they match the OEM ODX container, below), so
# they are preserved; the CPU, crypto and SA2 are corrected here. A genuinely
# different, TriCore TC1784 "DL382" also exists (Audi longitudinal, 8W_927155);
# this module is the Conti SH-2A variant.
#
# ---- SECURITY ACCESS (0x27) — SA2 seed->key, the real thing ----
# Source: OEM ODX-F flash container FL_ACxOEEEFE___P3E0.odx (ODXCreate_DL382),
#   <SECURITY-METHOD>SA2</SECURITY-METHOD>
#   <FW-SIGNATURE>6802814993A55A55AA4A05878105952668058249845AA5AA558703F780134C
# and the matching DL382_C1_MC_SC_ECUMEM20_Florian.ocnf <SA2> (same tape, minus
# the trailing 0x4C END opcode). Validated in sa2_seed_key.Sa2SeedKey:
#   seed 0x11223344 -> key 0x7F5EEED3 ; seed 0 -> 0xF972A84B.
# Decoded algorithm (32-bit register = seed):
#   2x RSL ; ADD 0xA55A55AA ; BCC +7 ; EOR 0x81059526 ; 5x RSR ;
#   SUB 0x5AA5AA55 ; EOR 0x03F78013 ; END
# NB a second config (DL382Gen2_komp.ocnf) ends the final EOR with 0x03F74321
# instead (key 0x7F5E2DE1) — a different SW/mem variant. The flashable ODX
# container uses 0x03F78013, so that is what ships here.
dsg_sa2_script = bytes.fromhex(
    "6802814993A55A55AA4A05878105952668058249845AA5AA558703F78013"
)

# ---- FRF UPDATE BLOCKS ----
# From FL_ACxOEEEFE___P3E0.odx: four flash blocks, each a DB_0xERASEDATA +
# DB_0xDATA pair, source-start-address (block id) 0x01..0x04.
#   id  name        UCS (uncompressed)    ECM    CRC32 (this SW)
#   01  DB_01DATA   1835008 = 0x1C0000    0x10   077723FB   (ASW+CAL)
#   02  DB_02DATA    262144 = 0x40000     0x10   F274508F
#   03  DB_03DATA     32768 = 0x8000      0x00   D828C590
#   04  DB_04DATA    131072 = 0x20000     0x00   FA40714C
# ECM (ENCRYPT-COMPRESS-METHOD): 0x10 = LZSS10 compression, NO encryption on the
# two large blocks; 0x00 = stored plain on the two small ones. There is no AES
# and no RSA signature on this ECU (unlike DQ381/DQ500-0DL). ALFID = 0x41.
dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

# Module block int == source-start-address / on-wire block identifier.
block_identifiers_dsg = {1: 0x01, 2: 0x02, 3: 0x03, 4: 0x04}

block_transfer_sizes_dsg = {1: 0x800, 2: 0x800, 3: 0x800, 4: 0x800}

software_version_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0], 3: [0x0, 0x0], 4: [0x0, 0x0]}

box_code_location_dsg = {1: [0x0, 0x0], 2: [0x0, 0x0], 3: [0x0, 0x0], 4: [0x0, 0x0]}

block_lengths_dsg = {
    1: 0x1C0000,  # DB_01 ASW+CAL (1835008)
    2: 0x40000,   # DB_02        (262144)
    3: 0x8000,    # DB_03        (32768)
    4: 0x20000,   # DB_04        (131072)
}

# CPU flash addresses (file offset + 0x80000000). FD_01/FD_02 confirmed against a
# full flat bin; FD_03/FD_04 provisional (boot half). Kept from prior RE.
block_base_address_dsg = {
    1: 0x800C0000,  # DB_01 ASW+CAL
    2: 0x80080000,  # DB_02
    3: 0x80040000,  # DB_03  (provisional)
    4: 0x80020000,  # DB_04  (provisional)
}

# ---- CRC / block integrity ----
# Every block is verified by CRC-32 (ODX SECURITY-METHOD "CRC32_Conti",
# BlockChecksumLength=4, CRCalways=True), computed over the UNCOMPRESSED block
# data (BlockCRCcompressed=False). The ECU checks it via UDS RoutineControl
# 0x31 01 0202 <blockId> after RequestTransferExit; a mismatch rejects the block.
# The reflected CRC-32 table (poly 0xEDB88320) lives in the boot ROM at file
# 0x3A444. Expected values are per-SW, so they are computed at flash time rather
# than pinned here (placeholder FFFFFFFF); the values above are the reference
# ODX checksums for the R3E3/ABUOEAEGG sample.
block_checksums_dsg = {
    1: bytes.fromhex("FFFFFFFF"),
    2: bytes.fromhex("FFFFFFFF"),
    3: bytes.fromhex("FFFFFFFF"),
    4: bytes.fromhex("FFFFFFFF"),
}

block_names_frf_dsg = {1: "FD_01DATA", 2: "FD_02DATA", 3: "FD_03DATA", 4: "FD_04DATA"}

dsg_binfile_offsets = {
    1: 0xC0000,   # DB_01 ASW+CAL
    2: 0x80000,   # DB_02
    3: 0x40000,   # DB_03  (provisional)
    4: 0x20000,   # DB_04  (provisional)
}

dsg_binfile_size = 0x280000  # 2621440

dsg_project_name = "DL382"

# No encryption (ODX ECM low-nibble 0). LZSS10 compression is applied to blocks
# 1/2 by the flash transfer layer via the DataFormatIdentifier, not here.
dsg_crypto = plaintext.PlaintextCrypto()

block_name_to_int = {"ASW": 1, "DB_02": 2, "DB_03": 3, "DB_04": 4}

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

# SH-2A Conti bootloader splits block erase into phases and returns an NRC
# between them (same behaviour as DQ381 @0x80013470) — retry erase.
dsg_flash_info.erase_retries = 5

# The TriCore TC1784 "DL382" (box 0CK910255, spare part 8W0/8W1/8W2927155) ships
# FRFs with ENCRYPT-COMPRESS-METHOD "11" in the same block layout, encrypted with
# the DL501 substitution table. FRF extraction falls back to it; flashing keeps
# the plaintext crypto of the SH-2A unit above.
from lib.crypto import dsg  # noqa: E402

dsg_flash_info.alt_cryptos = [dsg.DSG("dl501_key.bin")]
