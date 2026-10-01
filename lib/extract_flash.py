import copy
import io
import xml.etree.ElementTree as ET
import zipfile
from frf import decryptfrf
import extractodx
from . import constants


class ExternContainer(Exception):
    """The FRF uses the newer ODX-F container (external hashed .bin blocks).

    Seen on later DSG generations (e.g. DQ400E SW 0461/0660/0860). The flash
    blocks are encrypted with a per-generation key that is not shipped in this
    repo, so they cannot be decoded here."""


def extract_flash_from_frf(
    frf_data: bytes, flash_info: constants.FlashInfo, is_dsg=False
):
    odx_data = extract_odx_from_frf(frf_data)
    return extract_data_from_odx(odx_data, flash_info, is_dsg)


def open_frf_zip(frf_data: bytes) -> zipfile.ZipFile:
    """Open an FRF payload as a zip, transparently handling three shapes:

    * encrypted FRF  -> decrypt with the FRF key, then unzip
    * plaintext zip  -> already a PK zip, unzip directly
    * nested wrapper -> outer plaintext zip whose only member is another .frf
                        (recursively unwrapped, inner layer is encrypted)
    """
    data = frf_data
    for _ in range(4):  # bounded: guards against pathological nesting
        if data[:2] == b"PK":
            zf = zipfile.ZipFile(io.BytesIO(data))
        else:
            decrypted = decryptfrf.decrypt_data(decryptfrf.read_key_material(), data)
            zf = zipfile.ZipFile(io.BytesIO(bytes(decrypted)))
        names = zf.namelist()
        has_odx = any(n.lower().endswith((".odx", ".odx-f")) for n in names)
        inner_frf = [n for n in names if n.lower().endswith(".frf")]
        if inner_frf and not has_odx:
            data = zf.read(inner_frf[0])
            continue
        return zf
    raise ValueError("too many nested FRF layers")


def extract_odx_from_frf(frf_data: bytes):
    zf = open_frf_zip(frf_data)
    names = zf.namelist()
    odx = [n for n in names if n.lower().endswith(".odx")]
    if odx:
        return zf.read(odx[0])
    if any(n.lower().endswith(".odx-f") for n in names):
        raise ExternContainer()
    # Fall back to the historical behaviour (first member is the ODX).
    return zf.read(names[0])


def extract_data_from_odx(
    odx_content: bytes, flash_info: constants.FlashInfo, is_dsg=False
):
    """Decode all flash blocks. Families with several key eras list fallbacks
    in flash_info.alt_cryptos; the first crypto that decodes every block wins.

    Blocks are returned keyed by FLASHDATA SHORT-NAME and, where the ODX uses
    different SHORT-NAMEs than flash_info.block_names_frf (e.g. DQ400E
    FD_30ERASEPROGRROUTI vs FD_2), additionally by the canonical name, resolved
    through the DATABLOCK SOURCE-START-ADDRESS (the stable block identifier)."""
    last_err = None
    for crypto in [None] + list(getattr(flash_info, "alt_cryptos", [])):
        fi = flash_info
        if crypto is not None:
            fi = copy.copy(flash_info)
            fi.crypto = crypto
        try:
            flash_data, allowed_boxcodes = extractodx.extract_odx(odx_content, fi, is_dsg)
            break
        except Exception as e:
            last_err = e
    else:
        raise last_err

    for short_name, block in shortname_to_block(odx_content, flash_info).items():
        canonical = flash_info.block_names_frf.get(block)
        if canonical and canonical not in flash_data and short_name in flash_data:
            flash_data[canonical] = flash_data[short_name]
    return (flash_data, allowed_boxcodes)


def shortname_to_block(odx_content: bytes, flash_info: constants.FlashInfo) -> dict:
    """Map each FLASHDATA SHORT-NAME -> block number via the DATABLOCK's
    SOURCE-START-ADDRESS (the block identifier, e.g. 0x30/0x50/0x51)."""
    id_to_block = {v: k for k, v in flash_info.block_identifiers.items()}
    root = ET.fromstring(odx_content)
    fd_by_id = {fd.get("ID"): fd for fd in root.findall(".//FLASHDATAS/FLASHDATA")}
    out = {}
    for db in root.findall(".//DATABLOCKS/DATABLOCK"):
        ssa = db.find(".//SEGMENT/SOURCE-START-ADDRESS")
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
