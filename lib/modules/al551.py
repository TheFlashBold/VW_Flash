import struct
import zlib

from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import al551

# AL551 (4G0927158* / 4H1927158*) — ZF gen2 8HPXY torque-converter automatic TCU
# ("ITCU2", ZX8U, SH-2A big-endian). EV_TCMAL551. Audi A6/A7/A8 longitudinal
# (e.g. 3.0 TFSI / 4.0 TFSI). Version string "ZP1X8U40xxxx" lives in the CAL block.
#
# Container: classic embedded ODX. Flash blocks use ENCRYPT-COMPRESS-METHOD "22":
# compressed with the ZF LZSS variant (5-bit count / 11-bit distance,
# lib/lzss_zf.py — NOT the DSG LZSS10) then XORed with the fixed repeating 19-byte
# ASCII key "CyA2008ZFVAGtcuxsam" (lib/crypto/al551.py). extractodx.py calls
# crypto.decrypt() then crypto.decompress().
#
# Four blocks (SOURCE-START-ADDRESS 01-04). Offsets from the block headers
# (0x876543xx; FD_1 +0x08 = 0x180200 = end of ASW, FD_4 +0x0C = 0x1FFDEC) and a
# full pcmflash read; FD_4 verified byte-exact against an OBD CAL read. The
# bootloader region (0x0-0x6000, 0x8000-0x20000) and 0x17FE00-0x180200 are NOT
# carried in the FRF and stay at the fill byte in the assembled 0x200000 image:
#   0x006000-0x007E00  FD_2  (id 02, 0x01E00)
#   0x020000-0x03FE00  FD_3  (id 03, 0x1FE00)
#   0x040000-0x17FE00  FD_1  ASW/program (id 01, 0x13FE00)
#   0x180200-0x200000  FD_4  CAL (id 04, 0x7FE00; ZFADINFO, box code + version)

dsg_control_module_identifier = ControlModuleIdentifier(0x7E9, 0x7E1)

# int -> SOURCE-START-ADDRESS (block identifier in the ODX)
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
    1: 0x13FE00,  # ASW / program
    2: 0x1E00,
    3: 0x1FE00,
    4: 0x7FE00,   # CAL
}

dsg_sa2_script = bytes.fromhex("00")

block_names_frf_dsg = {1: "FD_1", 2: "FD_2", 3: "FD_3", 4: "FD_4"}

dsg_binfile_offsets = {
    1: 0x40000,
    2: 0x6000,
    3: 0x20000,
    4: 0x180200,
}

dsg_binfile_size = 0x200000  # 2 MB flat flash image

dsg_project_name = "AL551"

dsg_crypto = al551.AL551()

block_name_to_int = {"ASW": 1, "FD_2": 2, "FD_3": 3, "CAL": 4}

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

# Block CRCs, ported from generic-frontend src/server/tuning/checksum/al551.ts.
# Every flash block starts with a header (magic 87 65 43 xx) whose checksum
# descriptor at +0x34 is {u16 0x0004, u16 0xFFFF, u32 start, u32 end (inclusive),
# u32 0xFFFFFFFF, u32 crc} (big endian). The CRC is the standard reflected CRC-32
# (zlib.crc32) over [start, end]; the range never covers the header. The CAL start
# varies per version (0x18C000..0x190000) and is read from the header. FD_2/FD_3
# (bootloader) carry the same CRC plus an RSA signature and are not meant to be
# edited. Works on the full image, not on FRF blocks: the ASW range may run up to
# 0x180000, past the end of FD_1 (0x17FE00). Absent blocks (erased, e.g. the ASW of
# an OBD CAL read) are skipped.
# (block name, header offset, range limit)
crc_blocks = [
    ("FD_2", 0x6000, 0x7E00),
    ("FD_3", 0x20000, 0x3FE00),
    ("ASW", 0x40000, 0x180000),
    ("CAL", 0x180200, 0x200000),
]
crc_range_field = 0x38
crc_field = 0x44


def _crc_range(data: bytes, header: int, limit: int):
    """CRC range [start, end) of a block, or None when the block is absent
    (erased, e.g. the ASW/boot area of an OBD CAL read) or the header is invalid."""
    if len(data) < limit or data[header:header + 3] != b"\x87\x65\x43":
        return None
    start, end_incl = struct.unpack_from(">II", data, header + crc_range_field)
    end = end_incl + 1
    if start < header + crc_field + 4 or end > limit or end <= start:
        return None
    return start, end


def checksum_image(data: bytes) -> list:
    """[(block name, crc offset, stored crc, calculated crc)] for every present block."""
    out = []
    for name, header, limit in crc_blocks:
        rng = _crc_range(data, header, limit)
        if rng is None:
            continue
        stored = struct.unpack_from(">I", data, header + crc_field)[0]
        out.append((name, header + crc_field, stored, zlib.crc32(data[rng[0]:rng[1]])))
    return out


def checksum_fix_image(data: bytes) -> bytes:
    """Return a copy of the image with every present block CRC recalculated."""
    img = bytearray(data)
    for name, header, limit in crc_blocks:
        rng = _crc_range(img, header, limit)
        if rng is not None:
            struct.pack_into(">I", img, header + crc_field, zlib.crc32(img[rng[0]:rng[1]]))
    return bytes(img)


dsg_flash_info.checksum_image = checksum_image
dsg_flash_info.checksum_fix_image = checksum_fix_image
