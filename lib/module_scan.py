"""MQB vehicle module scan: identification, long coding and DTCs per control module.

Read-only except write_coding(). Coding fields are decoded with generic label
definitions from data/coding_labels.json (same schema as simos.app's
CodingDefinition: module, partNumbers/boxCode, properties with byte, bitStart,
bitEnd, label, type, options). DTC texts come from data/dtcs.csv
(code,pcode,name,symbol). Without a matching entry the raw values are shown.

Long-coding write: 10 03 -> 2E F198 <tester id> -> 2E 0600 <coding>.
No SecurityAccess.
"""

import csv
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import udsoncan
from udsoncan import configs, exceptions, services
from udsoncan.client import Client

from . import constants
from .connections.connection_setup import connection_setup

logger = logging.getLogger("VWFlash")


@dataclass
class Module:
    address: int  # diagnostic address (hex, e.g. 0x09)
    name: str
    txid: int

    @property
    def rxid(self) -> int:
        # MQB physical addressing: 0x7E0..0x7E7 -> +8, 0x7xx -> +0x6A
        return self.txid + 8 if 0x7E0 <= self.txid <= 0x7E7 else self.txid + 0x6A


# MQB physical request IDs. 01/02/09/0F(Haldex)/19/44 are verified in this repo;
# the rest are the commonly used MQB IDs - every reply is shown with its own
# F187/F197, so a mismatch is visible in the output.
MQB_MODULES = [
    Module(0x01, "Engine", 0x7E0),
    Module(0x02, "Transmission", 0x7E1),
    Module(0x03, "Brakes 1 (ABS/ESC)", 0x713),
    Module(0x05, "Access/Start Authorization (Kessy)", 0x70B),
    Module(0x08, "Climate/HVAC", 0x746),
    Module(0x09, "Central Electrics (BCM J519)", 0x70E),
    Module(0x10, "Park/Steer Assist", 0x70A),
    Module(0x13, "Distance Regulation (ACC)", 0x757),
    Module(0x15, "Airbag", 0x715),
    Module(0x16, "Steering Column Electronics", 0x70C),
    Module(0x17, "Instruments", 0x714),
    Module(0x19, "Gateway", 0x710),
    Module(0x22, "AWD (Haldex)", 0x70F),
    Module(0x42, "Door Electronics Driver", 0x74A),
    Module(0x44, "Steering Assist (EPS)", 0x712),
    Module(0x52, "Door Electronics Passenger", 0x74B),
    Module(0x5F, "Information Electronics", 0x773),
    Module(0xA5, "Front Sensors Driver Assist", 0x74F),
]

IDENT_DIDS = {
    0xF187: "Part Number",
    0xF189: "Software Version",
    0xF191: "Hardware Number",
    0xF1A3: "Hardware Version",
    0xF197: "System Name",
    0xF18C: "Serial Number",
    0xF19E: "ODX File",
    0xF1A2: "ODX Version",
}
CODING_DID = 0x0600
TESTER_ID_DID = 0xF198

# testFailed | testFailedThisOperationCycle | pending | confirmed | testFailedSinceLastClear
DTC_STATUS_MASK = 0x2F


class _Raw(udsoncan.DidCodec):
    def encode(self, val):
        return bytes(val)

    def decode(self, payload):
        return bytes(payload)

    def __len__(self):
        raise udsoncan.DidCodec.ReadAllRemainingData


@dataclass
class ModuleResult:
    module: Module
    present: bool = False
    ident: dict = field(default_factory=dict)
    coding: Optional[bytes] = None
    dtcs: list = field(default_factory=list)  # (packed_code, status_byte)
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Connection handling
# --------------------------------------------------------------------------- #


def _retargetable(interface: str) -> bool:
    # BLE / USB bridges carry rx/tx IDs in every frame header -> one link, many modules.
    return interface.startswith(("BLEISOTP", "USBISOTP")) or interface == "TEST"


def _retarget(conn, module: Module):
    conn.rxid = module.rxid
    conn.txid = module.txid
    conn.empty_rxqueue()


def _client(conn, timeout: float) -> Client:
    config = dict(configs.default_client_config)
    config["data_identifiers"] = {did: _Raw for did in (*IDENT_DIDS, CODING_DID, TESTER_ID_DID)}
    config["request_timeout"] = timeout
    return Client(conn, config=config)


def _read_did(client: Client, did: int) -> Optional[bytes]:
    try:
        return client.read_data_by_identifier_first(did)
    except Exception:  # NRC, timeout or garbage: optional DID, keep going
        return None


def _query(client: Client, result: ModuleResult, read_dtcs: bool):
    # First request doubles as presence probe: a timeout means "no module".
    part = client.read_data_by_identifier_first(0xF187)
    result.present = True
    result.ident["Part Number"] = part
    for did, name in IDENT_DIDS.items():
        if did == 0xF187:
            continue
        value = _read_did(client, did)
        if value is not None:
            result.ident[name] = value
    result.coding = _read_did(client, CODING_DID)
    if read_dtcs:
        try:
            response = client.get_dtc_by_status_mask(DTC_STATUS_MASK)
            result.dtcs = [(d.id, d.status.get_byte_as_int()) for d in response.service_data.dtcs]
        except exceptions.NegativeResponseException as e:
            result.error = f"DTC read refused: {e.response.code_name}"


def scan_modules(interface: str, modules=None, read_dtcs=True, timeout=1.0,
                 interface_path=None, progress=None) -> list[ModuleResult]:
    modules = modules or MQB_MODULES
    results = []

    def run(conn, module):
        result = ModuleResult(module)
        try:
            # No `with`: Client.__exit__ would close the shared connection.
            _query(_client(conn, timeout), result, read_dtcs)
        except exceptions.TimeoutException:
            pass
        except Exception as e:  # keep scanning the remaining modules
            result.error = repr(e)
        return result

    if _retargetable(interface):
        conn = connection_setup(interface, txid=modules[0].txid, rxid=modules[0].rxid,
                                interface_path=interface_path, st_min=0)
        conn.open()
        try:
            for i, module in enumerate(modules):
                if progress:
                    progress(i, len(modules), module)
                _retarget(conn, module)
                results.append(run(conn, module))
        finally:
            conn.close()
    else:
        for i, module in enumerate(modules):
            if progress:
                progress(i, len(modules), module)
            conn = connection_setup(interface, txid=module.txid, rxid=module.rxid,
                                    interface_path=interface_path, st_min=0)
            conn.open()
            try:
                results.append(run(conn, module))
            finally:
                conn.close()
    return results


def write_coding(interface: str, module: Module, coding: bytes, interface_path=None,
                 wsc: int = 0, importer: int = 0, equipment: int = 0) -> bytes:
    """Write long coding (10 03, F198 tester id, 0600) and return the read-back."""
    conn = connection_setup(interface, txid=module.txid, rxid=module.rxid,
                            interface_path=interface_path, st_min=0)
    conn.open()
    try:
        client = _client(conn, 5)
        current = client.read_data_by_identifier_first(CODING_DID)
        if len(current) != len(coding):
            raise ValueError(
                f"coding length {len(coding)} != module coding length {len(current)}"
            )
        client.change_session(
            services.DiagnosticSessionControl.Session.extendedDiagnosticSession
        )
        try:
            client.write_data_by_identifier(
                TESTER_ID_DID, tester_id(wsc, importer, equipment)
            )
        except exceptions.NegativeResponseException as e:
            # Some modules don't need/accept F198; the coding write still works.
            logger.warning(f"F198 tester-id write refused ({e.response.code_name}), continuing")
        client.write_data_by_identifier(CODING_DID, coding)
        return client.read_data_by_identifier_first(CODING_DID)
    finally:
        conn.close()


def tester_id(wsc: int, importer: int, equipment: int) -> bytes:
    return bytes([
        (equipment >> 13) & 0xFF,
        (equipment >> 5) & 0xFF,
        ((equipment & 0x1F) << 3) | ((importer >> 7) & 7),
        ((importer << 1) | (wsc >> 16)) & 0xFF,
        (wsc >> 8) & 0xFF,
        wsc & 0xFF,
    ])


def module_by_address(address: int) -> Module:
    for module in MQB_MODULES:
        if module.address == address:
            return module
    raise KeyError(f"unknown module address {address:02X}")


# --------------------------------------------------------------------------- #
# Formatting / decoding
# --------------------------------------------------------------------------- #


def dtc_code(packed: int) -> str:
    """24-bit UDS DTC -> 'B10F4F0' style (SAE letter + 4 hex + failure type)."""
    letter = "PCBU"[(packed >> 22) & 3]
    return f"{letter}{(packed >> 8) & 0x3FFF:04X}{packed & 0xFF:02X}"


def _text(value: bytes) -> str:
    try:
        text = value.rstrip(b"\x00").decode("ascii")
        if text.isprintable():
            return text.strip()
    except UnicodeDecodeError:
        pass
    return value.hex(" ").upper()


class LabelData:
    """Coding label definitions and DTC texts from generic data files.

    data/coding_labels.json: list of definitions
        {"id": "...", "module": "09", "partNumbers": ["5Q0937084"],
         "boxCode": "...",            # optional, alternative to partNumbers
         "properties": [
            {"byte": 0, "bitStart": 0, "bitEnd": 0, "label": "...",
             "type": "boolean"},
            {"byte": 1, "bitStart": 4, "bitEnd": 6, "label": "...",
             "options": [{"value": 16, "label": "..."}]}   # value = masked
         ]}
    data/dtcs.csv: code,pcode,name,symbol (code = 24-bit UDS DTC, decimal)
    """

    def __init__(self, labels_path: Optional[Path] = None, dtcs_path: Optional[Path] = None):
        self.labels_path = labels_path or Path(constants.internal_path("data", "coding_labels.json"))
        self.dtcs_path = dtcs_path or Path(constants.internal_path("data", "dtcs.csv"))
        self._definitions = None
        self._dtcs = None

    @property
    def definitions(self) -> list:
        if self._definitions is None:
            try:
                self._definitions = json.loads(self.labels_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                logger.info(f"No coding labels loaded from {self.labels_path}: {e}")
                self._definitions = []
        return self._definitions

    def dtc_text(self, packed: int) -> Optional[str]:
        if self._dtcs is None:
            self._dtcs = {}
            try:
                with open(self.dtcs_path, encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        try:
                            self._dtcs[int(row["code"])] = f"{row['pcode']} {row['name']}".strip()
                        except (KeyError, ValueError):
                            continue
            except OSError as e:
                logger.info(f"No DTC texts loaded from {self.dtcs_path}: {e}")
        exact = self._dtcs.get(packed)
        if exact:
            return exact
        # Same fault, other failure-type byte.
        base = packed >> 8
        return next((t for c, t in self._dtcs.items() if c >> 8 == base), None)

    def pick_definition(self, address: int, part_number: str, prefer: Optional[str] = None):
        """Return (definition, alternative ids). Prefers an explicit id fragment,
        else the matching definition with the most properties."""
        module_id = f"{address:02X}"
        pn = re.sub(r"[^0-9A-Z]", "", part_number.upper())
        candidates = []
        for d in self.definitions:
            if str(d.get("module", "")).upper() != module_id:
                continue
            box = d.get("boxCode")
            parts = d.get("partNumbers")
            norm = lambda x: re.sub(r"[^0-9A-Z]", "", str(x).upper())
            if box:
                ok = pn.startswith(norm(box))
            else:
                ok = not parts or any(pn.startswith(norm(x)) for x in parts)
            if ok:
                candidates.append(d)
        if prefer:
            candidates = [
                d for d in candidates if prefer.upper() in str(d.get("id", "")).upper()
            ] or candidates
        if not candidates:
            return None, []
        best = max(candidates, key=lambda d: len(d.get("properties", [])))
        return best, [str(d.get("id", "?")) for d in candidates if d is not best]


@dataclass
class CodingField:
    byte: int
    lo: int  # first bit
    hi: int  # last bit (== lo for a single-bit switch)
    label: str
    options: list  # [(masked value, label)]; empty for a boolean switch

    @property
    def mask(self) -> int:
        return ((1 << (self.hi - self.lo + 1)) - 1) << self.lo

    @property
    def is_bit(self) -> bool:
        return not self.options

    def get(self, coding: bytes) -> int:
        return coding[self.byte] & self.mask

    def set(self, coding: bytearray, value: int):
        coding[self.byte] = (coding[self.byte] & ~self.mask & 0xFF) | (value & self.mask)


def parse_definition(definition: Optional[dict]) -> list[CodingField]:
    """Label definition properties -> coding fields in definition order."""
    fields = []
    for prop in (definition or {}).get("properties", []):
        try:
            byte, lo, hi = int(prop["byte"]), int(prop["bitStart"]), int(prop["bitEnd"])
        except (KeyError, ValueError, TypeError):
            continue
        label = prop.get("label") or f"Byte {byte}, bit {lo}-{hi}"
        options = []
        if prop.get("type") != "boolean":
            options = [(int(o["value"]), str(o.get("label", ""))) for o in prop.get("options") or []]
        fields.append(CodingField(byte, lo, hi, label, options))
    return fields


def decode_coding(coding: bytes, fields: list[CodingField]) -> list[str]:
    """Render coding against label fields: one line per bit / bit field."""
    out = []
    for f in fields:
        if f.byte >= len(coding):
            continue
        value = f.get(coding)
        bits = f"Bit {f.lo}" if f.lo == f.hi else f"Bit {f.lo}-{f.hi}"
        if f.is_bit:
            mark = "[x]" if value else "[ ]"
            out.append(f"  Byte {f.byte:02d} {bits:9s} {mark} {f.label}")
        else:
            match = [label for v, label in f.options if v == value]
            text = match[0] if match else "(value not in label definition)"
            out.append(f"  Byte {f.byte:02d} {bits:9s} {value:02X}  {f.label}: {text}")
    return out


def format_result(result: ModuleResult, labels: LabelData, label_hint: Optional[str] = None) -> list[str]:
    m = result.module
    lines = [f"Address {m.address:02X}: {m.name}  (0x{m.txid:03X}/0x{m.rxid:03X})"]
    if not result.present:
        lines[0] += "  -- no response"
        if result.error:
            lines.append(f"  error: {result.error}")
        return lines
    for name, value in result.ident.items():
        lines.append(f"  {name:17s}: {_text(value)}")
    if result.coding is not None:
        lines.append(f"  {'Coding':17s}: {result.coding.hex().upper()}")
        part = _text(result.ident.get("Part Number", b""))
        definition, alternatives = labels.pick_definition(m.address, part, label_hint)
        if definition:
            alt = f" (alternatives: {', '.join(alternatives)})" if alternatives else ""
            lines.append(f"  Labels: {definition.get('id', part)}{alt}")
            lines.extend(decode_coding(result.coding, parse_definition(definition)))
    if result.error:
        lines.append(f"  error: {result.error}")
    if result.dtcs:
        lines.append(f"  {len(result.dtcs)} fault(s):")
        for packed, status in result.dtcs:
            text = labels.dtc_text(packed) or ""
            lines.append(f"    {dtc_code(packed)}  status {status:02X}  {text}")
    else:
        lines.append("  No faults")
    return lines
