"""VAG gateway (J533) flash containers (formerly tools/extract_gateway_frf.py).
Used by VW_Flash.py --gateway --action extract_frf.

Extract VAG gateway (J533) flash containers into one flat, 0x00-filled .bin.

  MQB     5Q0907530*  .frf  ODX-F, method 00 (plain); flash DATA base 0x10000
  MQB     5QE907530*  .frf  ODX-F, method 00 (plain); base from block header
  MQB evo 5WA907530*  .frf  ODX-F, method A0 (LZSS10, no crypto); base from header
  PQ      8P0907530*  .sgo  SGML Object File (lib.containers.bosch, codec sgo-raw);
                            real block addresses from the container

Flash drivers / erase routines (DRIVE, ERASEDATA, ERASEROUTI) are not flash
content and are left out. The image starts at the block base rounded down to
1 MB (0 for low flash, so file offset == address there) and ends at the last data byte rounded up to 64 KB; gaps are 0x00.
Output: <part>_<version>[_<S|E>].bin; with an output directory also index.csv
with base/size.
"""
import csv, os, re, struct
import xml.etree.ElementTree as ET

from lib.containers import bosch as e
from extractodx import decompress_raw_lzss10

KEY = e.DEFAULT_KEY
ALIGN = 0x10000
START_ALIGN = 0x100000
SKIP_TYPES = ("DRIVE", "ERASE")


def txt(el, path):
    x = el.find(path)
    return x.text.strip() if x is not None and x.text else None


def string_pointer_score(d, base):
    """Count BE u32 values that point at a NUL-preceded ASCII string."""
    n, L = 0, len(d)
    for i in range(0, L - 3, 4):
        v = struct.unpack(">I", d[i:i + 4])[0] - base
        if 1 <= v < L - 8 and d[v - 1] == 0 and all(32 <= c < 127 for c in d[v:v + 6]):
            n += 1
    return n


# Headerless families: base proven by string-pointer hits (5Q0 1069: 474 @0x10000 vs <=14)
KNOWN_BASE = {"5Q0907530": 0x10000}


def data_base(data, part):
    # 5QE / 5WA header: u16 id, 0x0201, ..., BE u32 @0x10 = base + 0x30
    if data[2:4] == b"\x02\x01":
        return struct.unpack(">I", data[0x10:0x14])[0] - 0x30
    if part[:9] in KNOWN_BASE:
        return KNOWN_BASE[part[:9]]
    # unknown headerless layout -> pick base by string pointers
    cands = (0x0, 0x8000, 0x10000, 0x20000, 0x40000)
    scores = {b: string_pointer_score(data, b) for b in cands}
    best = max(scores, key=scores.get)
    if scores[best] < 3 * max(1, sorted(scores.values())[-2]):
        raise SystemExit(f"ambiguous base: {scores}")
    return best


def frf_blocks(frf):
    root = ET.fromstring(e.load_odx(frf, KEY))
    fdata = {fd.get("ID"): fd for fd in root.iter("FLASHDATA")}
    blocks = []
    for db in root.iter("DATABLOCK"):
        sn = txt(db, "SHORT-NAME")
        if any(t in sn for t in SKIP_TYPES):
            continue
        fd = fdata[db.find("FLASHDATA-REF").get("ID-REF")]
        method = txt(fd, "ENCRYPT-COMPRESS-METHOD")
        raw = bytes.fromhex(re.sub(r"\s", "", txt(fd, "DATA") or ""))
        usize = int(txt(db.find(".//SEGMENT"), "UNCOMPRESSED-SIZE"))
        if method == "00":
            data = raw
        elif method == "A0":
            data = bytes(decompress_raw_lzss10(raw, usize))
        else:
            raise SystemExit(f"{os.path.basename(frf)}: {sn} unsupported method {method}")
        if len(data) != usize:
            raise SystemExit(f"{os.path.basename(frf)}: {sn} size {len(data)} != {usize}")
        blocks.append((sn, data_base(data, os.path.basename(frf)[3:]), data))
    return blocks


def sgo_blocks(sgo):
    blocks, _codec = e.extract_frf(sgo, KEY)
    return [(b[0], b[1], b[3]) for b in blocks]


def out_name(path):
    n = os.path.basename(path)
    m = re.match(r"(?:FL[-_])?(\w{9}[A-Z]{0,2}?)[-_]+(\d{4})(?:[-_]+(?:V001[-_]+)?([SE]))?", n)
    if not m:
        return os.path.splitext(n)[0] + ".bin"
    return "_".join(p for p in m.groups() if p) + ".bin"


def extract_container(path, out_dir=None):
    """Decode one gateway FRF/SGO. Returns (image, ``<part>_<version>[_<S|E>].bin``);
    with ``out_dir`` the image's base/size/segments are recorded in index.csv."""
    path = str(path)
    try:
        blocks = sgo_blocks(path) if path.lower().endswith(".sgo") else frf_blocks(path)
    except SystemExit as ex:
        raise ValueError(str(ex)) from None
    # start on a 1 MB boundary (0 for low flash) so variants of one family
    # share file offsets (5WA: 0x1000000 and 0x1020000 layouts)
    lo = min(b for _, b, _ in blocks) & ~(START_ALIGN - 1)
    hi = max(b + len(d) for _, b, d in blocks)
    hi = (hi + ALIGN - 1) & ~(ALIGN - 1)
    img = bytearray(hi - lo)
    for _, b, d in blocks:
        img[b - lo:b - lo + len(d)] = d
    fn = out_name(path)
    if out_dir:
        segs = " ".join(f"0x{b:X}+0x{len(d):X}" for _, b, d in blocks)
        idx = os.path.join(str(out_dir), "index.csv")
        rows = {}
        if os.path.exists(idx):
            with open(idx) as f:
                rows = {r["file"]: r for r in csv.DictReader(f)}
        rows[fn] = {"file": fn, "base": f"0x{lo:X}", "size": f"0x{len(img):X}", "segments": segs}
        with open(idx, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["file", "base", "size", "segments"])
            w.writeheader()
            w.writerows(rows[k] for k in sorted(rows))
    return bytes(img), fn

