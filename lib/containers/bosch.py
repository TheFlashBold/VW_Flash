"""
Self-addressed Bosch-style flash containers (formerly extract_frf_edc17.py).
Used by VW_Flash.py --edc17 / --aisin / --sgo_raw --action extract_frf.

Extract a full flat binary from a VAG EDC17/MED17-style
Bosch "BCB Type1" flash container. Two carriers are auto-detected:

  * FRF/ODX  (ASAM ODX-F XML, EDC17 diesel / MED17), and
  * SGO      ("SGML Object File", Bosch engine-ECU .sgo). Same BCB Type1 codec;
             the container differs and each block payload is stored XOR-0xFF
             inverted. Handles MED17.5 (0x800xxxxx maps, 0x178000 image) and
             MED9.1 (0-based, 0x200000). Output is 0x00-filled to match the
             existing pcmflash-style dumps, named <box>_<ver>_<EPK>_<SWid>.bin.

Pipeline (FRF/ODX):
    FRF  --(recursive-XOR cipher, data/frf.key)-->  ZIP
    ZIP  --(unzip)-->  .odx  (ASAM ODX-F / ODX flash container, XML)
    .odx --(per FLASHDATA block)-->
            [SOURCE]/[CHECKSUM]/[FORMAT]/[START_ADDRESS]/[END_ADDRESS] text header
            + "1A 01" BCB header
            + BCB stream XOR'd with a repeating ASCII key
    BCB stream (u16-BE token model):
            token = u16 BE; flag = tok >> 14, len = tok & 0x3FFF
              flag 0 = literal : copy `len` bytes from the stream
              flag 1 = RLE     : repeat the next single byte `len` times
              flag 3 = end     : followed by a 24-bit BE checksum = sum(output)&0xFFFFFF
    Each decoded block is placed at (START_ADDRESS - base) in a 0xFF-filled image.

The repeating XOR key is auto-detected: known keys are tried first, then a
frequency-analysis fallback; every candidate is validated by the block's own
24-bit checksum, so a reported decode is always checksum-correct.

This is distinct from Simos AES/LZSS ODX blocks (see extractodx.py). Works on
EDC17C46 diesel ECUs such as 03L906018 (EA189 2.0 TDI).

The BCB token model, repeating-XOR key and keyless frequency recovery match the
AGPL reference prj/unpacksgo (github.com/prj/unpacksgo), which also documents an
EDC16-specific rolling-key algorithm and per-controller section maps. Newer
EDC17 variants (e.g. 03L906023MS) use a different codec and are NOT handled here.
"""
import argparse
import collections
import io
import os
import re
import struct
from pathlib import Path
from zipfile import ZipFile

# Community-known repeating-XOR keys for Bosch BCB streams. Any hit is still
# checksum-verified, so a wrong key can never yield a false decode.
KNOWN_KEYS = [
    b"BiWbBuD101", b"GEHEIM", b"CodeRobert", b"MILKYWAY", b"Mst2Bosch",
]

# Bosch engine-ECU "SGML Object File" container magic (the .sgo carrier). The
# BCB Type1 codec inside is identical to the FRF/ODX path below; only the
# container differs and each block payload is stored XOR-0xFF inverted.
SGO_MAGIC = b"SGML Object File"

_HDR_RE = re.compile(
    rb"\[START_ADDRESS\]\n([0-9A-Fa-f]+)\n\[END_ADDRESS\]\n([0-9A-Fa-f]+)\n")
_CHK_RE = re.compile(rb"\[CHECKSUM\]\n([0-9A-Fa-f]+)\n")


def decrypt_frf(data: bytes, key_material: bytes) -> bytes:
    """Undo the FRF "recursive XOR" cipher (same as frf/decryptfrf.py)."""
    out = bytearray()
    first_seed, second_seed, ki = 0, 1, 0
    for b in data:
        kb = key_material[ki]
        first_seed = ((first_seed + kb) * 3) & 0xFF
        out.append(b ^ (first_seed ^ 0xFF ^ second_seed ^ kb))
        second_seed = ((second_seed + 1) * first_seed) & 0xFF
        ki = (ki + 1) % len(key_material)
    return bytes(out)


def _xor(s: bytes, k: bytes) -> bytes:
    return bytes(s[i] ^ k[i % len(k)] for i in range(len(s)))


def bcb_decompress(stream: bytes):
    """Return (output, end_checksum) or (None, None) on a malformed stream."""
    p, out = 0, bytearray()
    n = len(stream)
    while p + 2 <= n:
        tok = (stream[p] << 8) | stream[p + 1]
        p += 2
        flag, ln = tok >> 14, tok & 0x3FFF
        if flag == 0:                       # literal run
            if p + ln > n:
                return None, None
            out += stream[p:p + ln]
            p += ln
        elif flag == 1:                     # RLE run
            if p >= n:
                return None, None
            out += bytes([stream[p]]) * ln
            p += 1
        elif flag == 3:                     # end + 24-bit checksum
            if p + 3 > n:
                return None, None
            return bytes(out), (stream[p] << 16) | (stream[p + 1] << 8) | stream[p + 2]
        else:                               # flag 2 = invalid
            return None, None
    return None, None


def _recover_key(stream: bytes, klen: int) -> bytes:
    """Frequency-analysis key recovery: the most common byte in each key column
    is assumed to correspond to a plaintext 0x00 (long zero/erase regions)."""
    cols = [collections.Counter() for _ in range(klen)]
    for i, b in enumerate(stream):
        cols[i % klen][b] += 1
    return bytes(cols[c].most_common(1)[0][0] for c in range(klen))


def decode_block(stream0: bytes, want_len: int, want_chk: int):
    """Decode one XOR'd BCB stream (already past the '1A 01' header).
    Returns (data, key) with size + checksum verified, or (None, None)."""
    def verify(s):
        out, chk = bcb_decompress(s)
        if (out is not None and chk is not None
                and len(out) in (want_len, want_len + 1)
                and (sum(out) & 0xFFFFFF) == chk
                and (want_chk is None or chk == want_chk)):
            return out
        return None

    for k in KNOWN_KEYS:
        out = verify(_xor(stream0, k))
        if out is not None:
            return out, k
    # fallback: recover the key from byte statistics (checksum is the oracle)
    for klen in range(1, 33):
        k = _recover_key(stream0, klen)
        out = verify(_xor(stream0, k))
        if out is not None:
            return out, k
    return None, None


def parse_odx(odx_bytes: bytes):
    """Yield (short_name, start_addr, end_addr, header_checksum, xored_stream)
    for each non-erase FLASHDATA block."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(odx_bytes)
    for fd in root.iter("FLASHDATA"):
        sn = fd.find("SHORT-NAME")
        sn = sn.text if sn is not None else ""
        if "ERASE" in sn:
            continue
        data_el = fd.find(".//DATA")
        if data_el is None or not data_el.text:
            continue
        raw = bytes.fromhex(data_el.text)
        hm = _HDR_RE.search(raw)
        if not hm:
            continue
        sa, ea = int(hm.group(1), 16), int(hm.group(2), 16)
        cm = _CHK_RE.search(raw)
        hdr_chk = int(cm.group(1), 16) if cm else None
        # Locate the "1A 01" BCB header. Usually right after the text header, but
        # search the whole block in both the raw and 0xFF-XOR'd domains (per
        # prj/unpacksgo) so SGO-style / inverted blocks also work.
        stream0 = None
        for dom in (raw[hm.end():], raw, _xor(raw, b"\xFF")):
            i = dom.find(b"\x1A\x01")
            if i >= 0:
                stream0 = dom[i + 2:]
                break
        if stream0 is None:
            continue
        yield sn, sa, ea, hdr_chk, stream0


def parse_sgo(data: bytes):
    """Yield (short_name, start, end, header_checksum, xored_stream) for each
    block of a Bosch engine-ECU "SGML Object File" (.sgo).

    Container: magic (16) + u32-LE offset table + version descriptor + baud
    descriptors + SA2 script (u32-LE length-prefixed) + blocks. Each block has a
    0x19-byte header: btype at +3, 3-byte big-endian flash address at +0, u32-LE
    payload length at +0x15, payload at +0x19. The payload is stored XOR-0xFF
    inverted; undoing that reveals the same ``[START_ADDRESS]``.. text header +
    ``1A 01`` BCB stream that the FRF/ODX blocks carry."""
    u32 = lambda o: struct.unpack_from("<I", data, o)[0]
    b3 = lambda o: (data[o] << 16) | (data[o + 1] << 8) | data[o + 2]
    iv4 = data.index(0)
    p = u32(iv4 + 0x19)          # -> SA2 script (u32-LE length-prefixed)
    p = p + 4 + u32(p)           # skip past it to the first block
    while p + 0x19 <= len(data):
        length = u32(p + 0x15)
        if length == 0 or p + 0x19 + length > len(data):
            break
        raw = bytes(x ^ 0xFF for x in data[p + 0x19 : p + 0x19 + length])
        p += 0x19 + length
        hm = _HDR_RE.search(raw)
        if not hm:
            # older BCB header (1997-2005): one text line "<path>.BCx <date> <time>
            # <chk24>" + "BCB Type1 (C) R.Bosch" banner; address range from the
            # SGO block header (start @+7, length @+4, both 3-byte BE)
            om = re.search(rb"\.BC\w \d\d\.\d\d\.\d{4} [\d:]+ +([0-9A-F]{6})\r?\n\r?BCB Type1", raw)
            if not om:
                continue
            hdr = data[p - 0x19 - length:p - length]
            sa = int.from_bytes(hdr[7:10], "big")
            ea = sa + int.from_bytes(hdr[4:7], "big") - 1     # +4 = payload length
            i = raw.find(b"\x1A\x01", om.end())
            if i < 0 or ea <= sa:
                continue
            path = re.search(rb"\\([^\\]+)\.BC\w ", raw)
            yield (path.group(1).decode("latin1") if path else f"BLOCK_{sa:08X}"), sa, ea, int(om.group(1), 16), raw[i + 2:]
            continue
        sa, ea = int(hm.group(1), 16), int(hm.group(2), 16)
        cm = _CHK_RE.search(raw)
        hdr_chk = int(cm.group(1), 16) if cm else None
        i = raw.find(b"\x1A\x01", hm.end())
        if i < 0:
            continue
        sm = re.search(rb"\[SOURCE\]\n([^\n_]+)", raw)   # Bosch SW id, e.g. M08Z40
        sn = sm.group(1).decode("latin1") if sm else f"BLOCK_{sa:08X}"
        yield sn, sa, ea, hdr_chk, raw[i + 2:]


def parse_sgo_aisin(data: bytes):
    """Aisin 09G927750 / 09G997750 (older 09G generation, Renesas SH, BE) .sgo:
    same SGML container, but each block is the raw flash content XOR 0xFF with
    no text header / BCB stream.  0x19-byte block header: 3-byte BE start
    address at +0, u32-BE length at +3, u32-LE length at +0x15 (must agree)."""
    u32 = lambda o: struct.unpack_from("<I", data, o)[0]
    iv4 = data.index(0)
    p = u32(iv4 + 0x19)
    p = p + 4 + u32(p)
    while p + 0x19 <= len(data):
        length = u32(p + 0x15)
        if length == 0 or p + 0x19 + length > len(data):
            break
        sa = int.from_bytes(data[p:p + 3], "big")
        if int.from_bytes(data[p + 3:p + 7], "big") != length:
            return
        raw = bytes(x ^ 0xFF for x in data[p + 0x19:p + 0x19 + length])
        p += 0x19 + length
        yield f"BLOCK_{sa:06X}", sa, sa + length - 1, raw


def _sgo_bytes(path: str) -> bytes:
    """Raw SGO bytes, transparently unzipping ZIP-wrapped .sgo files."""
    data = Path(path).read_bytes()
    if data[:2] == b"PK":
        zf = ZipFile(io.BytesIO(data))
        return zf.read(zf.namelist()[0])
    return data


def frf_to_odx(frf_path: str, key_path: str) -> bytes:
    key_material = Path(key_path).read_bytes()
    enc = Path(frf_path).read_bytes()
    zf = ZipFile(io.BytesIO(decrypt_frf(enc, key_material)))
    name = zf.namelist()[0]
    return zf.read(name), name


def build_image(blocks, fill=0xFF, base=None):
    """Lay each decoded block at ``sa - base`` into a ``fill``-filled image.
    ``base`` defaults to the lowest block address (FRF/ODX); SGO callers pass an
    explicit base (0x80000000 for MED17-style maps, 0 otherwise) so the region
    below the first block is included rather than trimmed away."""
    decoded = [(sn, sa, ea, data) for (sn, sa, ea, data) in blocks]
    if base is None:
        base = min(sa for _, sa, _, _ in decoded)
    top = max(sa + len(data) for _, sa, _, data in decoded)
    img = bytearray([fill]) * (top - base)
    for _, sa, _, data in decoded:
        img[sa - base:sa - base + len(data)] = data
    return bytes(img), base


# --- Newer XML-ODX codec (e.g. EDC17C64 / 04L906021*): ENCRYPT-COMPRESS-METHOD
# "A1" = compression 'A' (LZSS10, 6-bit count / 10-bit disp) + encryption '1'
# (repeating-XOR BiWbBuD101). Distinct from the older bracket-text BCB above,
# whose method is "11". Both are wrapped in the same ASAM ODX-F XML. ---

_ECM_RE = re.compile(rb"<ENCRYPT-COMPRESS-METHOD[^>]*>\s*([0-9A-Za-z]+)\s*<")


# --- Aisin 09G (AQ250 / TF-60SN) ODX: two logical blocks, each an ERASEDATA
# stub plus a DATA segment with ENCRYPT-COMPRESS-METHOD "a0" (LZSS10, no XOR).
# SOURCE-START-ADDRESS only carries the block number, so the image offsets come
# from a full 2 MB read (09G927749B_2855 verified byte-exact):
#   FD_0DATA (code, 0x186000) @ 0x5A000, FD_1DATA (calibration, 0x53000) @ 0x7000.
# Sanity limit for any laid-out image (largest real reads are 10 MB).
MAX_IMAGE_SIZE = 64 * 1024 * 1024
AISIN_09G_IMAGE_SIZE = 0x200000
# Block name variants seen across 09G927749/750/158: FD_0DATA/FD_1DATA and
# FD_01DATA/FD_02DATA. ENCRYPT-COMPRESS-METHOD "a0" = LZSS10, "00" = raw.
AISIN_09G_BLOCKS = {  # name variants -> (image offset, size)
    ("FD_0DATA", "FD_01DATA"): (0x5A000, 0x186000),   # code
    ("FD_1DATA", "FD_02DATA"): (0x7000, 0x53000),     # calibration
}


def _odx_data_blocks(odx_bytes):
    """Map FLASHDATA short-name suffix -> (ecm, uncompressed size, raw bytes)."""
    text = odx_bytes.decode("latin1")
    sizes = {}
    for m in re.finditer(r"<DATABLOCK\b.*?</DATABLOCK>", text, re.S):
        blk = m.group(0)
        ref = re.search(r'<FLASHDATA-REF ID-REF="[^"]*?\.?([^".]+)"', blk)
        us = re.search(r"<UNCOMPRESSED-SIZE>(\d+)", blk)
        if ref and us:
            sizes[ref.group(1)] = int(us.group(1))
    blocks = {}
    for m in re.finditer(r'<FLASHDATA\b[^>]*ID="[^"]*?\.?([^".]+)"[^>]*>(.*?)</FLASHDATA>', text, re.S):
        name, body = m.group(1), m.group(2)
        dm = re.search(r"<DATA>([0-9A-Fa-f]+)</DATA>", body)
        em = re.search(r"<ENCRYPT-COMPRESS-METHOD[^>]*>([^<]*)<", body)
        if dm and em:
            blocks[name] = (em.group(1).strip().lower(), sizes.get(name), bytes.fromhex(dm.group(1)))
    return blocks


def _aisin_09g_blocks(odx_bytes):
    """Return [(name, offset, size, ecm, raw)] if the ODX matches the Aisin 09G
    two-block layout, else None."""
    if b"09G9" not in odx_bytes[:20000]:
        return None
    blocks = _odx_data_blocks(odx_bytes)
    found = []
    for names, (off, size) in AISIN_09G_BLOCKS.items():
        name = next((n for n in names if n in blocks), None)
        if name is None:
            return None
        ecm, usize, raw = blocks[name]
        if ecm not in ("a0", "00") or usize != size:
            return None
        found.append((name, off, size, ecm, raw))
    return found


def is_aisin_09g_odx(odx_bytes):
    return _aisin_09g_blocks(odx_bytes) is not None


def parse_odx_aisin_09g(odx_bytes):
    """Yield (short_name, start, end, data) with start/end as 0-based image offsets."""
    from extractodx import decompress_raw_lzss10
    for name, off, size, ecm, raw in _aisin_09g_blocks(odx_bytes):
        out = bytes(decompress_raw_lzss10(raw, size)) if ecm == "a0" else raw
        if len(out) != size:
            raise SystemExit(f"{name}: got {len(out):#x} bytes, expected {size:#x}")
        yield name, off, off + size - 1, out


AISIN_09S_IMAGE_SIZE = 0x400000
# CAL image offset by CAL block size; code follows the CAL block directly.
# Verified code-relative: AQ250/AQ450 (Ver80x) against the 09S927158CP_3917 read,
# AQ300 (Ver900) by CAL directory ptrs (0x90000..) and absolute code ptrs -> prologues.
AISIN_09S_CAL_OFFSETS = {0x58000: 0x8000,     # AQ250/AQ450 Ver80x: code 0x60000..0x3C8000
                         0x98000: 0x10000}    # AQ300 Ver900:       code 0xA8000..0x3D0000


def _aisinaw_decompress(raw):
    """Newer Aisin (09S, AQ250/AQ300/AQ450 on V850E2): 'AISINAW ' + u16 LE chunk
    count, last-chunk size, chunk size (0x1800) + u16 LE compressed size per
    chunk; every chunk is a raw LZMA1 stream (lc=3 lp=0 pb=2)."""
    import lzma
    if raw[:8] != b"AISINAW ":
        raise SystemExit("not an AISINAW block")
    n, last, cs = struct.unpack_from("<HHH", raw, 8)
    sizes = struct.unpack_from(f"<{n}H", raw, 14)
    p, out = 14 + 2 * n, bytearray()
    for i, s in enumerate(sizes):
        want = cs if i < n - 1 else last
        d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[
            dict(id=lzma.FILTER_LZMA1, lc=3, lp=0, pb=2, dict_size=1 << 13)])
        chunk = d.decompress(raw[p:p + s], max_length=want)
        if len(chunk) != want:
            raise SystemExit(f"AISINAW chunk {i}: got {len(chunk):#x} bytes, expected {want:#x}")
        out += chunk
        p += s
    return bytes(out)


def _aisin_09s_blocks(odx_bytes):
    """(code, cal) raw payloads if this is a 2-block AISINAW ODX, else None."""
    blocks = [(n, b) for n, b in _odx_data_blocks(odx_bytes).items()
              if b[1] and b[1] > 1 and b[2][:8] == b"AISINAW "]
    if len(blocks) != 2:
        return None
    blocks.sort(key=lambda nb: -nb[1][1])          # code block is the larger one
    return blocks


def parse_odx_aisin_09s(odx_bytes):
    """Yield (short_name, start, end, data): CAL at its layout offset, code right after it."""
    (cn, (_, csize, craw)), (kn, (_, ksize, kraw)) = _aisin_09s_blocks(odx_bytes)
    cal, code = _aisinaw_decompress(kraw), _aisinaw_decompress(craw)
    if len(cal) != ksize or len(code) != csize:
        raise SystemExit("AISINAW block size mismatch")
    base = AISIN_09S_CAL_OFFSETS.get(len(cal))
    if base is None:
        raise SystemExit(f"AISINAW: unknown CAL size {len(cal):#x}")
    co = base + len(cal)
    yield kn, base, co - 1, cal
    yield cn, co, co + len(code) - 1, code


def detect_odx_codec(odx_bytes):
    """'lzss10' if any data block uses compression 'A' (newer EDC17, e.g. C64),
    else 'bcb' (older bracket-text BCB, e.g. C46). Both are XML ODX; the method's
    first character is the compression selector."""
    for m in _ECM_RE.finditer(odx_bytes):
        if m.group(1)[:1] in (b"A", b"a"):
            return "lzss10"
    return "bcb"


def parse_odx_lzss10(odx_bytes):
    """Yield (short_name, start_addr, end_addr, data) for newer XML-ODX blocks.
    Each block: unxor(BiWbBuD101) -> LZSS10 -> plaintext of <UNCOMPRESSED-SIZE>.
    Start/end come from the decoded block's 32-byte descriptor (bytes[12:16] LE =
    end address, base 0x80000000), so no address map is needed."""
    import struct
    from extractodx import decompress_raw_lzss10
    text = odx_bytes.decode("latin1")
    sizes = {}
    for m in re.finditer(r"<DATABLOCK\b.*?</DATABLOCK>", text, re.S):
        blk = m.group(0)
        ref = re.search(r'<FLASHDATA-REF ID-REF="([^"]+)"', blk)
        us = re.search(r"<UNCOMPRESSED-SIZE>(\d+)", blk)
        if ref and us:
            sizes[ref.group(1)] = int(us.group(1))
    for m in re.finditer(r"<FLASHDATA\b([^>]*)>(.*?)</FLASHDATA>", text, re.S):
        attrs, body = m.group(1), m.group(2)
        idm = re.search(r'ID="([^"]+)"', attrs)
        snm = re.search(r"<SHORT-NAME>([^<]+)", body)
        sn = snm.group(1) if snm else (idm.group(1) if idm else "?")
        if "ERASE" in sn:
            continue
        dm = re.search(r"<DATA>([0-9A-Fa-f]+)</DATA>", body)
        ecmm = re.search(r"<ENCRYPT-COMPRESS-METHOD[^>]*>([^<]*)<", body)
        if not dm or not ecmm:
            continue
        ecm = ecmm.group(1).strip()
        size = sizes.get(idm.group(1)) if idm else None
        raw = bytes.fromhex(dm.group(1))
        stage = _xor(raw, KNOWN_KEYS[0]) if ecm[1:2] == "1" else raw
        out = bytes(decompress_raw_lzss10(stage, size))
        end_abs = struct.unpack("<I", out[12:16])[0]
        ea = end_abs + 4
        sa = ea - len(out)
        yield sn, sa, ea, out


# EPK / box-code identity in a decoded image, e.g. "EDC17_C46/5/P643//C643X5F8"
# (C46) or the "//C866DA78H///" form (C64). The token after "//" is the EPK.
_EPK_RE = re.compile(rb"EDC17[_ ]?C[0-9A-Za-z]+/[0-9]+/P[0-9A-Za-z]+//([0-9A-Za-z]+)")
_EPK_FALLBACK_RE = re.compile(rb"//(C[0-9]{3}[0-9A-Za-z]{3,8})/")
# Bosch MED/EDC identity string, e.g. "MED17/5/MED17.5//D175X55H_M08Z40/Dst00//"
# or "MED91/5/4420.01//D915E_N48A210/..." -> token "<EPK>_<SW id>".
_MED_ID_RE = re.compile(rb"MED\d+/\d+/[0-9A-Za-z.]+//([0-9A-Z]+_[0-9A-Z]+)/")


def extract_epk(img):
    m = _MED_ID_RE.search(img)
    if m:
        return m.group(1).decode()
    m = _EPK_RE.search(img)
    if m:
        return m.group(1).decode()
    m = _EPK_FALLBACK_RE.search(img)
    return m.group(1).decode() if m else None


def output_name(frf_path, epk):
    """<boxcode>_<version>_<epk>.bin from the FRF filename (11-char box code +
    version), runs of '_' collapsed to one."""
    stem = re.sub(r"\.(frf|odx|sgo)$", "", os.path.basename(frf_path), flags=re.I)
    stem = re.sub(r"^FL[_-]", "", stem)
    box = stem[:11].rstrip("_-")
    rest = stem[11:].lstrip("_-")
    parts = [box, rest] + ([epk] if epk else [])
    return re.sub(r"_+", "_", "_".join(p for p in parts if p)) + ".bin"


def load_odx(path, key):
    """Return ODX XML bytes from any wrapping: raw ODX, a zip (possibly zip-wrapped
    FRF, as in some archives), or a recursive-XOR FRF (optionally nested)."""
    key_material = Path(key).read_bytes()

    def unwrap(data, depth=0):
        if depth > 6:
            raise SystemExit(f"{os.path.basename(path)}: too many wrapper layers")
        if data.lstrip()[:5] == b"<?xml":
            return data
        if data[:2] == b"PK":
            zf = ZipFile(io.BytesIO(data))
            return unwrap(zf.read(zf.namelist()[0]), depth + 1)
        # otherwise assume a recursive-XOR FRF payload
        return unwrap(decrypt_frf(data, key_material), depth + 1)

    return unwrap(Path(path).read_bytes())


def extract_sgo(path):
    """Decode a Bosch engine-ECU .sgo (SGML Object File) into a list of
    (short_name, start_addr, end_addr, data) blocks. Each block is verified by
    its own 24-bit BCB checksum."""
    data = _sgo_bytes(path)
    if data[:16] != SGO_MAGIC:
        raise SystemExit(f"{os.path.basename(path)}: not an SGML Object File")
    blocks = []
    for sn, sa, ea, hdr_chk, stream0 in parse_sgo(data):
        out, _key = decode_block(stream0, ea - sa + 1, hdr_chk)
        if out is None:
            raise SystemExit(f"{os.path.basename(path)}: {sn} decode failed")
        blocks.append((sn, sa, ea, out))
    if not blocks:
        raise SystemExit(f"{os.path.basename(path)}: no blocks decoded")
    return blocks


def extract_frf(path, key):
    """Auto-detect the container/codec and return (blocks, codec) where blocks
    is a list of (short_name, start_addr, end_addr, data). Raises on failure."""
    if _sgo_bytes(path)[:16] == SGO_MAGIC:
        if re.match(r"09[GD]9[0-9]7750", os.path.basename(path), re.I):
            blocks = list(parse_sgo_aisin(_sgo_bytes(path)))
            if not blocks:
                raise SystemExit(f"{os.path.basename(path)}: Aisin SGO block layout not recognised")
            return blocks, "aisin09g-sgo"
        try:
            return extract_sgo(path), "sgo-bcb"
        except SystemExit:
            # non-Bosch suppliers (Marelli AMT, Siemens transfer case, ...): raw
            # flash content XOR 0xFF with the Aisin-style block header
            blocks = list(parse_sgo_aisin(_sgo_bytes(path)))
            if not blocks:
                raise
            return blocks, "sgo-raw"
    odx = load_odx(path, key)
    if odx.lstrip()[:5] != b"<?xml":
        raise SystemExit(f"{os.path.basename(path)}: could not obtain ODX XML")
    if _aisin_09s_blocks(odx) is not None:
        return list(parse_odx_aisin_09s(odx)), "aisin09s"
    codec = "aisin09g" if is_aisin_09g_odx(odx) else detect_odx_codec(odx)
    if codec != "aisin09g" and b"<SHORT-NAME>FL_09G9" in odx[:20000]:
        # Aisin container with a block layout we have not mapped yet: the
        # Bosch fallback would read bogus addresses from the payload.
        raise SystemExit(f"{os.path.basename(path)}: Aisin 09G ODX with unknown block layout")
    blocks = []
    if codec == "aisin09g":
        blocks = list(parse_odx_aisin_09g(odx))
    elif codec == "lzss10":
        for sn, sa, ea, out in parse_odx_lzss10(odx):
            blocks.append((sn, sa, ea, out))
    else:
        for sn, sa, ea, hdr_chk, stream0 in parse_odx(odx):
            out, key_used = decode_block(stream0, ea - sa + 1, hdr_chk)
            if out is None:
                raise SystemExit(f"{os.path.basename(path)}: {sn} decode failed")
            blocks.append((sn, sa, ea, out))
    if not blocks:
        raise SystemExit(f"{os.path.basename(path)}: no blocks decoded")
    return blocks, codec


DEFAULT_KEY = str(Path(__file__).resolve().parents[2] / "data" / "frf.key")

# Codec groups selectable from VW_Flash.py (extract_frf auto-detects the codec).
CODECS_BOSCH = {"bcb", "lzss10", "sgo-bcb"}
CODECS_AISIN = {"aisin09g", "aisin09s", "aisin09g-sgo"}
CODECS_SGO_RAW = {"sgo-raw"}


def extract_container(path, out_dir=None, codecs=None, key=DEFAULT_KEY):
    """Decode one FRF/ODX/SGO into a flat image. Returns (image, file name
    <boxcode>_<version>_<epk>.bin). Raises ValueError on failure or when the
    detected codec is not in ``codecs``."""
    path = str(path)
    try:
        blocks, codec = extract_frf(path, key)
    except SystemExit as e:
        raise ValueError(str(e)) from None
    if codecs and codec not in codecs:
        raise ValueError(f"{os.path.basename(path)}: container codec {codec!r} "
                         f"is not one of {sorted(codecs)}")
    if codec == "sgo-bcb":
        # SGO maps use absolute 0x800xxxxx (MED17) or 0-based (MED9.1)
        # addresses; keep the region below the first block and 0x00-fill
        # gaps to match the existing pcmflash-style dumps.
        hint = 0x80000000 if all(sa >= 0x80000000 for _, sa, _, _ in blocks) else 0
        img, base = build_image(blocks, fill=0x00, base=hint)
    elif codec == "sgo-raw":
        img, base = build_image(blocks, fill=0xFF, base=0)
    elif codec == "aisin09g-sgo":
        # older 09G (SH): 512 KB / 1 MB flash, boot below the block and the
        # NVM/data tail are not in the container -> 0xFF like an erased read
        img, base = build_image(blocks, fill=0xFF, base=0)
        size = 0x80000 if len(img) <= 0x80000 else 0x100000
        img = img + b"\xff" * (size - len(img))
    elif codec == "aisin09g":
        # Full 2 MB read layout; regions outside the two blocks (boot etc.)
        # are not in the container and stay 0x00.
        img, base = build_image(blocks, fill=0x00, base=0)
        img = img + bytes(AISIN_09G_IMAGE_SIZE - len(img))
    elif codec == "aisin09s":
        # 4 MB read layout (09S927158CP_3917 read: CAL 0x8000, code to 0x3C8000;
        # AQ300: CAL 0x10000, code to 0x3D0000);
        # boot and the data tail are not in the container -> 0x00 like 09G
        img, base = build_image(blocks, fill=0x00, base=0)
        img = img + bytes(AISIN_09S_IMAGE_SIZE - len(img))
    else:
        img, base = build_image(blocks)
    if len(img) > MAX_IMAGE_SIZE:
        raise ValueError(f"{os.path.basename(path)}: refusing {len(img):#x}-byte image "
                         f"(> {MAX_IMAGE_SIZE:#x}); block addresses are not plausible")
    return img, output_name(path, extract_epk(img))

