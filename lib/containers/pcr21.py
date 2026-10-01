"""
Siemens/Continental PCR2.1 FRF containers (formerly tools/extract_pcr21_frf.py).
Used by VW_Flash.py --pcr21 --action extract_frf.

Unpack Siemens/Continental PCR2.1 (Simos PCR2.1, EA189
1.6/2.0 TDI CR, 03L906023*) FRF flash containers into flat 2 MB bins.

Pipeline per file:
    FRF --(recursive-XOR, vw_flash/data/frf.key)--> ODX (ASAM ODX, 3SOFT Filename2ODX)
    ODX --per <FLASHDATA> FD_1/2/3, ENCRYPT-COMPRESS-METHOD "11"-->
        enc '1'  = SimosXor (byte ^ (i & 0xFF), same as legacy Simos 03F906070)
        comp '1' = legacy Simos LZSS (vw_flash/lib/legacysimos.decompress:
                   hdr = signifier, offset bits, len bits, BE32 size, ...)

Block placement (2 MB image, 0xFF fill) — matches the common 2 MB OBD/bench reads
where the CAL CAS header sits at 0x180014:
    FD_1  boot/CBOOT  0x1FE00  -> 0x020000
    FD_2  ASW         0x13FE00 -> 0x040000
    FD_3  CAL         0x7AE00  -> 0x180000

Verified: FL_03L906023MP_9971.frf FD_2/FD_3 byte-identical to a customer
0x227200-byte read of the same SW (that tool's layout: FD_1 0xC000, FD_2 0x20000,
FD_3 0x1AC400).

Output name: <part>_<ver>_<EPK>.bin, EPK = CAL[0x23:0x30] (e.g. SM2G0M0000000).
"""
import binascii
import io
import os
import tempfile
import zipfile
import re
from pathlib import Path

from lib.containers import bosch as EF
from lib import legacysimos
from lib.crypto.simos_xor import SimosXor

DEFAULT_FRF_KEY = EF.DEFAULT_KEY
IMAGE_SIZE = 0x200000
PLACEMENT = {"1": 0x020000, "2": 0x040000, "3": 0x180000}
EPK_SLICE = slice(0x23, 0x30)

_FD_RE = re.compile(r'<FLASHDATA[^>]*ID="([^"]+)"[^>]*>(.*?)</FLASHDATA>', re.S)


def load_odx(path: str, key: str) -> str:
    data = Path(path).read_bytes()
    if data[:4] == b"PK\x03\x04":
        # outer plain ZIP around the XOR-encrypted inner FL_*.frf
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            inner = z.read(z.namelist()[0])
        with tempfile.NamedTemporaryFile(suffix=".frf") as t:
            t.write(inner)
            t.flush()
            return load_odx(t.name, key)
    if data.lstrip()[:5] != b"<?xml":
        data, _ = EF.frf_to_odx(path, key)
    return data.decode("latin1")


def sizes(odx: str) -> dict:
    """FLASHDATA id -> (block number, uncompressed size) for TYPE="DATA" blocks.
    Two ID styles occur: FD_1 (3SOFT Filename2ODX) and FD_01DATA (newer)."""
    out = {}
    for m in re.finditer(r'<DATABLOCK [^>]*TYPE="DATA"[^>]*>(.*?)</DATABLOCK>', odx, re.S):
        body = m.group(1)
        ref = re.search(r'<FLASHDATA-REF ID-REF="([^"]+)"', body).group(1)
        num = re.search(r"\.FD_0*(\d+)", ref).group(1)
        size = int(re.search(r"<UNCOMPRESSED-SIZE>(\d+)<", body).group(1))
        out[ref] = (num, size)
    return out


def decode(ecm: str, raw: bytes, size: int) -> bytes:
    data = SimosXor().decrypt(raw) if ecm[1:2] == "1" else raw
    if ecm[0:1] == "1":
        data = bytes(legacysimos.decompress(data))
    if len(data) != size:
        raise ValueError(f"size mismatch {len(data):#x} != {size:#x}")
    return data


def extract(path: str, key: str):
    odx = load_odx(path, key)
    want = sizes(odx)
    blocks = {}
    for m in _FD_RE.finditer(odx):
        fid, body = m.group(1), m.group(2)
        if fid not in want:
            continue  # ERASE stubs
        bid, size = want[fid]
        ecm = re.search(r"<ENCRYPT-COMPRESS-METHOD[^>]*>([^<]*)<", body).group(1)
        data = re.search(r"<DATA>([0-9A-Fa-f]*)</DATA>", body).group(1)
        blocks[bid] = decode(ecm, binascii.unhexlify(data), size)
    if sorted(blocks) != ["1", "2", "3"]:
        raise ValueError(f"unexpected block set {sorted(blocks)}")
    if blocks["3"][0x14:0x17] != b"CAS":
        raise ValueError("CAL block has no CAS header")
    img = bytearray(b"\xff" * IMAGE_SIZE)
    for bid, blk in blocks.items():
        base = PLACEMENT[bid]
        img[base:base + len(blk)] = blk
    return bytes(img), blocks


def out_name(frf: str, img: bytes) -> str:
    stem = Path(frf).stem.replace("-", "_")
    m = re.match(r"FL_(03L906023\w*?)_+(\d{4})(.*)$", stem)
    part, ver, extra = (m.group(1), m.group(2), m.group(3)) if m else (stem, "", "")
    epk = img[0x180000:][EPK_SLICE].decode("latin1", "replace").strip("\x00 ")
    return f"{part}_{ver}{extra}_{epk}.bin"


def extract_container(path, out_dir=None):
    """Decode one PCR2.1 FRF. Returns (image, ``<part>_<ver>_<EPK>.bin``)."""
    img, _ = extract(str(path), DEFAULT_FRF_KEY)
    return img, out_name(str(path), img)

