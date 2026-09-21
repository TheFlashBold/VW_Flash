#!/usr/bin/env python3
"""
Batch-unpack VAG DSG FRF files into full flat bins named <boxcode>_<version>.bin.

Decrypts each FRF -> ODX, decrypts+decompresses the flash blocks via the chosen
DSG module (substitution/AES + LZSS10), and assembles a full flat image
(0x00-filled gaps, blocks at the module's binfile offsets). Existing outputs are
skipped.

Container shapes handled transparently:
  * encrypted FRF   -> decrypt with the FRF key, unzip, read the .odx
  * plaintext zip   -> already a PK zip
  * nested wrapper  -> outer plaintext zip whose only member is another .frf
  * ODX-F (extern)  -> external hashed .bin blocks; seen on newer DSG gens whose
                       per-gen key is not shipped here -> reported BLOCKED.

Blocks are matched to module block ids by the DATABLOCK SOURCE-START-ADDRESS
(stable), not by FLASHDATA SHORT-NAME (which varies between FRF families, e.g.
FD_2/FD_3/FD_4 vs FD_30ERASEPROGRROUTI/FD_50FLASHDATA/FD_51FLASHDATA for DQ400E).
--prefix matching is tolerant of '-' vs '_' separators.

Example (all 0GC / DQ381 files):
    python3 unpack_dsg_frf.py --module dq381 --prefix FL_0GC300 \
        --src ~/Downloads/drive_bins --dst ../bin/dsg/DQ381

Example (DQ400E, both spare-part and SW part numbers):
    python3 unpack_dsg_frf.py --module dq400 --prefix FL_0DD \
        --src ~/Downloads/drive_bins --dst ../bin/dsg/DQ400E
"""
import argparse
import io
import os
import re
import sys
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from extractodx import extract_odx                     # noqa: E402
from frf.decryptfrf import decrypt_data, read_key_material  # noqa: E402
from lib.modules import (  # noqa: E402
    dq200mqb, dq250mqb, dq381, dq400mqb, dq500_0bh, dq500_0dl, dl501, vl381, dl382,
    al991,
)

MODULES = {
    "dq250": dq250mqb,
    "dq381": dq381,
    "dq400": dq400mqb,
    "dq500-0dl": dq500_0dl,
    "dq500-0bh": dq500_0bh,
    "dq200": dq200mqb,
    "dl501": dl501,
    "vl381": vl381,
    "dl382": dl382,
    "al991": al991,
}

# Some families ship multiple crypto keys across SW eras. When a block fails to
# decode with the module's default crypto, retry with these alternates.
# DQ200 0CW: default is the "late" table; older SW uses the "early" table.
def _dq200_alt_cryptos():
    from lib.crypto.dq200 import DQ200
    return [DQ200("late"), DQ200("early")]

ALT_CRYPTOS = {"dq200": _dq200_alt_cryptos}

# FL_<boxcode>_<version>_<...>.frf   e.g. FL_0GC300012A_1423_OcWY_sw.frf
# Some FRFs use '-' as the separator instead of '_' (e.g. FL-0DD300045H-0518-RJJV-sw.frf).
# The boxcode field can be dash-padded to a fixed width, producing runs of
# separators (e.g. FL-4G5927156---0004.frf, FL-8K5927156B--0004.frf), so allow
# one or more separator chars between fields.
_NAME_RE = re.compile(r"^FL[-_]+([0-9A-Za-z]+)[-_]+([0-9A-Za-z]+)(?:[-_].*)?\.frf$")


class ExternContainer(Exception):
    """The FRF uses the newer ODX-F container (external hashed .bin blocks).

    Seen on later DSG generations (e.g. DQ400E SW 0461/0660/0860). The flash
    blocks are encrypted with a per-generation key that is not shipped in this
    repo, so they cannot be decoded here."""


def _open_frf_zip(data: bytes) -> ZipFile:
    """Open an FRF payload as a zip, transparently handling three shapes:

    * encrypted FRF  -> decrypt with the FRF key, then unzip
    * plaintext zip  -> already a PK zip, unzip directly
    * nested wrapper -> outer plaintext zip whose only member is another .frf
                        (recursively unwrapped, inner layer is encrypted)
    """
    for _ in range(4):  # bounded: guards against pathological nesting
        if data[:2] == b"PK":
            zf = ZipFile(io.BytesIO(data))
        else:
            zf = ZipFile(io.BytesIO(bytes(decrypt_data(read_key_material(), data))))
        names = zf.namelist()
        has_odx = any(n.lower().endswith((".odx", ".odx-f")) for n in names)
        inner_frf = [n for n in names if n.lower().endswith(".frf")]
        if inner_frf and not has_odx:
            data = zf.read(inner_frf[0])
            continue
        return zf
    raise ValueError("too many nested FRF layers")


def frf_to_odx_bytes(frf_path: Path) -> bytes:
    zf = _open_frf_zip(frf_path.read_bytes())
    names = zf.namelist()
    odx = [n for n in names if n.lower().endswith(".odx")]
    if odx:
        return zf.read(odx[0])
    if any(n.lower().endswith(".odx-f") for n in names):
        raise ExternContainer()
    # Fall back to the historical behaviour (first member is the ODX).
    return zf.read(names[0])


def shortname_to_block(odx_bytes: bytes, mod) -> dict:
    """Map each FLASHDATA SHORT-NAME -> module block int via the DATABLOCK's
    SOURCE-START-ADDRESS (the block identifier, e.g. 0x30/0x50/0x51).

    SHORT-NAMEs are not portable across FRF families (FD_2/FD_3/FD_4 vs
    FD_30ERASEPROGRROUTI/...), but the SOURCE-START-ADDRESS is, so we key on it.
    """
    import xml.etree.ElementTree as ET
    id_to_block = {v: k for k, v in mod.block_identifiers_dsg.items()}
    root = ET.fromstring(odx_bytes)
    fd_by_id = {fd.get("ID"): fd for fd in root.findall(".//FLASHDATAS/FLASHDATA")}
    out = {}
    for db in root.findall(".//DATABLOCKS/DATABLOCK"):
        seg = db.find(".//SEGMENT")
        ssa = seg.find("SOURCE-START-ADDRESS")
        ref = db.find(".//FLASHDATA-REF")
        if ssa is None or ref is None or ssa.text is None:
            continue
        try:
            block = id_to_block[int(ssa.text.strip(), 16)]
        except (ValueError, KeyError):
            continue
        fd = fd_by_id.get(ref.get("ID-REF"))
        if fd is not None and fd.find("SHORT-NAME") is not None:
            out[fd.find("SHORT-NAME").text.strip()] = block
    return out


def assemble(data_blocks: dict, sn_to_block: dict, mod, fill: int = 0x00) -> bytes:
    """Assemble a flat image. data_blocks is {short_name: bytes} (from
    extract_odx); sn_to_block maps those names to module block ints."""
    blocks_by_id = {}
    for sn, data in data_blocks.items():
        bid = sn_to_block.get(sn)
        if bid is not None:
            blocks_by_id[bid] = data
    img = bytearray([fill]) * mod.dsg_binfile_size
    for bid, off in mod.dsg_binfile_offsets.items():
        blk = blocks_by_id.get(bid)
        if blk is None:
            raise KeyError(f"missing block id {bid} "
                           f"(0x{mod.block_identifiers_dsg[bid]:02x})")
        img[off:off + len(blk)] = blk
    return bytes(img)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--module", required=True, choices=sorted(MODULES))
    ap.add_argument("--prefix", default="FL_0GC300",
                    help="filename prefix filter (default FL_0GC300)")
    ap.add_argument("--src", required=True, help="folder with .frf files")
    ap.add_argument("--dst", required=True, help="output folder for .bin files")
    ap.add_argument("--fill", type=lambda x: int(x, 0), default=0x00,
                    help="gap fill byte (default 0x00)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)

    mod = MODULES[a.module]
    src, dst = Path(a.src), Path(a.dst)
    dst.mkdir(parents=True, exist_ok=True)

    # Match the prefix tolerant of '-' vs '_' separators.
    norm = lambda s: s.replace("-", "_")
    files = sorted(p for p in src.iterdir()
                   if p.name.endswith(".frf")
                   and norm(p.name).startswith(norm(a.prefix)))
    print(f"{len(files)} FRF matching {a.prefix!r}")

    done = skipped = failed = 0
    for p in files:
        m = _NAME_RE.match(p.name)
        if not m:
            print(f"  SKIP (name) {p.name}")
            skipped += 1
            continue
        boxcode, version = m.group(1), m.group(2)
        out = dst / f"{boxcode}_{version}.bin"
        if out.exists():
            skipped += 1
            continue
        if a.dry_run:
            print(f"  would write {out.name}")
            done += 1
            continue
        try:
            odx = frf_to_odx_bytes(p)
            # Try the module's default crypto, then any alternates for this family.
            import copy
            cryptos = [None]
            if a.module in ALT_CRYPTOS:
                cryptos = ALT_CRYPTOS[a.module]()
            data_blocks = None
            last_err = None
            for cr in cryptos:
                fi = mod.dsg_flash_info
                if cr is not None:
                    fi = copy.copy(fi)
                    fi.crypto = cr
                try:
                    data_blocks, _ = extract_odx(odx, fi, is_dsg=True)
                    break
                except Exception as e:
                    last_err = e
                    data_blocks = None
            if data_blocks is None:
                raise last_err
            sn_to_block = shortname_to_block(odx, mod)
            img = assemble(data_blocks, sn_to_block, mod, a.fill)
            out.write_bytes(img)
            print(f"  OK {out.name}  ({len(img):#x})")
            done += 1
        except ExternContainer:
            print(f"  BLOCKED {p.name}: ODX-F container (newer gen) — "
                  f"decryption key not available in this repo")
            failed += 1
        except Exception as e:
            print(f"  FAIL {p.name}: {e!r}")
            failed += 1

    print(f"\nwritten={done} skipped(existing/name)={skipped} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
