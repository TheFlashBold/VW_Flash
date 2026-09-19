#!/usr/bin/env python3
"""Unpack pre-MQB DQ250 (02E, Temic) DSG ``.sgo`` firmware files.

Pre-MQB DSG software ships as "SGML Object File" containers (magic
``SGML Object File``) rather than the ODX/FRF used by MQB (0D9) boxes.  Each
container holds one or more flash blocks (ASW / CAL) whose payload is encrypted
with the rolling substitution cipher implemented in
``lib.crypto.dsg_premqb`` (see that module for the algorithm).

This tool parses the container, decrypts every block with the pre-MQB cipher,
lays the decrypted blocks at their flash addresses into a flat image, and names
the result ``<boxcode>_<version>.bin`` (matching the existing DQ250 dumps in
``bin/dsg/DQ250/``).

Usage:
    python3 unpack_dsg_sgo.py <out_dir> <file.sgo> [more.sgo ...]
    python3 unpack_dsg_sgo.py <out_dir> --glob 'frf/*.sgo'
"""
import glob
import os
import re
import struct
import sys
import zipfile

from lib.crypto.dsg_premqb import DSGPreMQB

MAGIC = b"SGML Object File"
IMAGE_SIZE = 0x178000  # pre-MQB 02E flash image size (matches existing dumps)


def _raw(path: str) -> bytes:
    """Return the SGO bytes, transparently unzipping ZIP-wrapped .sgo files."""
    data = open(path, "rb").read()
    if data[:2] == b"PK":
        zf = zipfile.ZipFile(path)
        return zf.read(zf.infolist()[0].filename)
    return data


def parse_blocks(data: bytes):
    """Yield (btype, addr, length, payload) for every block in the container.

    Container layout: magic (16) + u32-LE offset table + version descriptor
    (XOR 0xFF) + baud descriptors + SA2 script (u32-LE length prefixed) + blocks.
    Each block has a 0x19-byte header: btype at +3, 3-byte big-endian flash
    address at +0, u32-LE payload length at +0x15, payload at +0x19.
    """
    u32 = lambda o: struct.unpack_from("<I", data, o)[0]
    b3 = lambda o: (data[o] << 16) | (data[o + 1] << 8) | data[o + 2]
    iv4 = data.index(0)
    sa2ptr = u32(iv4 + 0x19)
    sa2len = u32(sa2ptr)
    p = sa2ptr + 4 + sa2len
    out = []
    while p + 0x19 <= len(data):
        length = u32(p + 0x15)
        if length == 0 or p + 0x19 + length > len(data):
            break
        out.append((data[p + 3], b3(p), length, data[p + 0x19 : p + 0x19 + length]))
        p = p + 0x19 + length
    return out


def descriptor_version(data: bytes) -> str:
    """The container version string lives right after the magic, XORed 0xFF."""
    seg = bytes(b ^ 0xFF for b in data[0x10:0x60])
    return seg.split(b"\x00")[0].decode("latin1", "replace")


def image_version(image: bytes) -> str:
    """The full version string ``v0698x3402ec__getriebe_DSG_MP8x F93S`` is
    embedded in the decoded firmware (the container descriptor only holds the
    filename-style variant without the FxxS/Exx family marker)."""
    m = re.search(rb"v069[\x20-\x7e]{6,48}", image)
    return m.group()[:48].decode("latin1", "replace") if m else ""


def version_label(verstr: str) -> str:
    """Derive the ``9334``-style label: 2 digits from the FxxS/Exx family
    marker + the 2-digit revision that precedes ``02ea``/``02ec``."""
    rev = None
    m = re.search(r"(\d{2})02e[ac]", verstr)
    if m:
        rev = m.group(1)
    fam = None
    m = re.search(r"[FE](\d{2})S?", verstr)
    if m:
        fam = m.group(1)
    if fam and rev:
        return fam + rev
    return rev or fam or "0000"


def find_boxcode(image: bytes) -> str:
    # Newer builds carry a 10-char boxcode (02E300057A); older ones a 9-char
    # stem space-padded with no revision letter (02E300052).
    m = re.search(rb"02E3\d{5}[A-Z]?", image)
    return m.group().decode().rstrip() if m else None


TABLES = ("A", "B")  # A = later 02E generation, B = older (low-revision) firmware


def _assemble(blocks, cipher):
    end = max((a + l for _, a, l, _ in blocks), default=0)
    image = bytearray(max(IMAGE_SIZE, end))
    for _btype, addr, length, payload in blocks:
        image[addr : addr + length] = cipher.decrypt(payload)
    return bytes(image)


def unpack(path: str, table: str = None):
    """Decrypt an SGO into a flat image.  With ``table=None`` (default), each
    per-platform key table is tried until the output looks like DSG firmware."""
    data = _raw(path)
    if data[:16] != MAGIC:
        raise ValueError(f"not an SGML Object File: {path}")
    blocks = parse_blocks(data)
    for t in (table,) if table else TABLES:
        image = _assemble(blocks, DSGPreMQB(t))
        if table or looks_decoded(image):
            return image
    return image  # last attempt; caller checks looks_decoded()


def looks_decoded(image: bytes) -> bool:
    """A correct decrypt contains the DSG firmware signature; a wrong table
    yields high-entropy garbage.  (The assembled image is mostly 0x00 padding
    regardless of the key, so a zero-run test is not sufficient; and a bare
    "DSG" can appear by chance, so require the full signature.)"""
    return b"getriebe" in image


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    out_dir = argv[1]
    if argv[2] == "--glob":
        files = sorted(glob.glob(argv[3]))
    else:
        files = argv[2:]
    os.makedirs(out_dir, exist_ok=True)
    ok = bad = 0
    for f in files:
        try:
            image = unpack(f)
        except Exception as e:  # noqa: BLE001
            print(f"SKIP {os.path.basename(f)}: {e}")
            bad += 1
            continue
        if not looks_decoded(image):
            print(f"WRONGKEY {os.path.basename(f)} -- needs another table")
            bad += 1
            continue
        box = find_boxcode(image)
        label = version_label(image_version(image))
        name = f"{box}_{label}.bin" if box else f"{label}_{os.path.basename(f)}.bin"
        open(os.path.join(out_dir, name), "wb").write(image)
        print(f"OK   {name:28} <- {os.path.basename(f)}")
        ok += 1
    print(f"\n{ok} decoded, {bad} skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
