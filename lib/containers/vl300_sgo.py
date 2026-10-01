"""Audi Multitronic VL300 (01J, Temic C167) ``.sgo`` containers (formerly
unpack_vl300_sgo.py). Used by VW_Flash.py --vl300 --action extract_frf.

Covers the x910155/156/157/159 single-block containers (flash 0x8000 len
0x78000).  Container parsing is shared with the pre-MQB DQ250 tool; the cipher
is ``lib.crypto.vl300`` (tables T1/T2 auto-selected).  Multi-block Bosch
``[SOURCE] BCB Type1`` SGOs with the same part-number stem (e.g. 4F0910157E,
x910156 engine ECUs) are NOT VL300 -- use ``VW_Flash.py --edc17`` for those.

Output: flat 0x80000 image (0x00..0x8000 = bootloader, not in the SGO, zero
filled), named ``<partno>_<version>.bin``.  Offsets in the VL300 OLS
("Komplette Bin", 0x78000) = image offset - 0x8000.
"""
import os
import re

from lib.crypto.vl300 import TABLES, VL300
from lib.modules import vl300 as vl300_module
from lib.containers.dsg_premqb_sgo import MAGIC, _raw, parse_blocks

IMAGE_SIZE = vl300_module.dsg_binfile_size
SIGNATURE = b"VL300 Standard"


def unpack_ex(path: str, table: str = None):
    """Return ``(image, table)``; ``table`` is None if no table fits."""
    data = _raw(path)
    if data[:16] != MAGIC:
        raise ValueError("not an SGML Object File")
    blocks = parse_blocks(data)
    if not blocks or blocks[0][1] != vl300_module.dsg_binfile_offsets[1] or blocks[0][3][:8] == bytes(b ^ 0xFF for b in b"[SOURCE]"):
        raise ValueError("not a VL300 container " + str([(hex(a), hex(l)) for _, a, l, _ in blocks]))
    for t in (table,) if table else TABLES:
        cipher = VL300(t)
        image = bytearray(IMAGE_SIZE)
        for _btype, addr, length, payload in blocks:
            image[addr : addr + length] = cipher.decrypt(payload)
        if SIGNATURE in image:
            return bytes(image), t
    return bytes(image), None


def name_for(path: str) -> str:
    # 8E0910159B--0020.sgo / 8E0910159B__0020.sgo -> 8E0910159B_0020
    stem = os.path.basename(path).rsplit(".", 1)[0]
    m = re.match(r"(\w{3}910\d{3}[A-Z]?)[-_]+(\w{4})$", stem)
    return f"{m.group(1)}_{m.group(2)}" if m else stem


def extract_container(path, out_dir=None):
    """Decode one VL300 SGO. Returns (image, ``<partno>_<version>.bin``)."""
    image, table = unpack_ex(str(path))
    if table is None:
        raise ValueError(f"{os.path.basename(str(path))}: no VL300 table fits -- needs another table")
    return image, name_for(str(path)) + ".bin"

