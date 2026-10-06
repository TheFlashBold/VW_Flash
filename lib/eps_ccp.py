"""
EPS proprietary CCP/XCP-on-CAN read over the esp32-isotp-ble-bridge RAW CAN mode.

This reads the MQB electric-power-steering (ZF, 3Q0/5Q0909144*) per-car
parametrization out of ECU flash (0x61000..0x63000, 8 KB) non-destructively, by
speaking the EPS proprietary CCP measurement channel over *raw* 8-byte CAN
frames (NOT ISO-TP). It reuses the existing BLE transport
(lib/connections/ble_isotp_connection.BLEISOTPConnection) in its raw-CAN mode.

It is completely isolated from the ISO-TP flashing path and does not touch it.

------------------------------------------------------------------------------
Bring-up / test procedure (this CANNOT be tested without hardware):
  1. Flash the esp32-isotp-ble-bridge firmware that implements RAW CAN MODE
     (setting 9). See esp32-isotp-ble-bridge/RAW_CAN_MODE.md.
  2. Power the EPS (ignition on) and put the dongle on a CAN bus that reaches it.
  3. FIRST confirm the channel answers and learn the response (DTO) id:
       python3 VW_Flash.py --eps --action sniff_ccp --interface BLEISOTP \
           [--ble_name BLE_TO_ISOTP20] [--sniff_seconds 5]
     It enters raw mode, sends CONNECT and prints every observed (id, data)
     frame. The reply to CONNECT comes back on the ECU's DTO id with a leading
     status byte 0xFF.
  4. Dump the per-car parametrization (flash 0x61000..0x63000):
       python3 VW_Flash.py --eps --action dump_ccp --output_bin eps_param.bin \
           --interface BLEISOTP

------------------------------------------------------------------------------
Protocol (established; raw 8-byte CAN frames):
  CRO (command-receive) id = EXTENDED 29-bit 0x07FC9600  (default; override).
  DTO (data-transmit/reply) id = UNKNOWN -> discovered by sniffing.
  Commands (byte[0], operands little-endian):
    CONNECT   FF 00 00 00 00 00 00 00        (sets channel-enable bit; no seed)
    SET-MTA   F6 00 00 <bank> <addr LE32>    (bank ignored)
    UPLOAD    F5 <N>  00 00 00 00 00 00       (reads N bytes from MTA, auto-inc)
    ONE-SHOT  F4 <N>  00 00 <addr LE32>       (N<=7; sets addr + one reply frame)
  Reply frame = status byte (0xFF ok / 0xFE err) + up to 7 data bytes. For N>7
  the ECU keeps emitting reply frames until N bytes are exhausted; the last
  frame may carry fewer than 7 data bytes (shorter DLC).

Values that still need verification on a real car are flagged in the report and
in comments: the DTO id (discovered, never hardcoded), reply timing, and the
maximum N accepted per UPLOAD (we default to a conservative chunk).
"""

import logging
import time

from lib.connections.connection_setup import connection_setup

logger = logging.getLogger("VWFlash")
frame_logger = logging.getLogger("CANFrames")

# EPS CCP command-receive object id (extended 29-bit). Override via dump CLI.
EPS_CRO_ID = 0x07FC9600

# Per-car parametrization region in EPS flash (non-destructive read).
EPS_PARAM_START = 0x61000
EPS_PARAM_LENGTH = 0x2000  # 8 KB

# CCP-ish command bytes (byte[0] of the 8 CAN data bytes).
CMD_CONNECT = 0xFF
CMD_SET_MTA = 0xF6
CMD_UPLOAD = 0xF5
CMD_SHORT_UPLOAD = 0xF4

# Reply status byte.
STATUS_OK = 0xFF
STATUS_ERR = 0xFE

# Bytes requested per UPLOAD. Each reply frame carries up to 7 data bytes, so N
# bytes => ceil(N/7) frames. Kept conservative for reliability over promiscuous
# BLE (frames can be dropped on a busy bus); the real max-N is unverified on a
# car. Tune with --upload_chunk.
DEFAULT_UPLOAD_CHUNK = 0x40  # 64 bytes -> 10 reply frames per UPLOAD


class EpsCcpError(Exception):
    pass


class EpsCcpChannel:
    """A raw-CAN EPS CCP session over the BLE bridge.

    Typical use is via the module-level helpers dump_eps_parametrization() and
    sniff_ccp(), but the class can be driven directly:

        ch = EpsCcpChannel("BLEISOTP_AA:BB:CC:DD:EE:FF")
        ch.open()
        try:
            ch.connect()
            ch.discover_dto()
            data = ch.dump()
        finally:
            ch.close()
    """

    def __init__(self, interface, cro_id=EPS_CRO_ID, interface_path=None):
        self.interface = interface
        self.interface_path = interface_path
        self.cro_id = cro_id
        self.conn = None
        self.dto_id = None

    # -- lifecycle --------------------------------------------------------
    def open(self):
        # rxid/txid are unused in raw mode (raw frames carry their own 29-bit
        # arbitration id in the payload); pass 0/0.
        self.conn = connection_setup(
            self.interface,
            txid=0,
            rxid=0,
            interface_path=self.interface_path,
        )
        self.conn.open()
        self.conn.enter_raw_mode()

    def close(self):
        if self.conn is None:
            return
        try:
            self.conn.exit_raw_mode()
        except Exception as e:  # never let cleanup mask the real error
            logger.warning("EPS CCP: exit raw mode failed: %s", e)
        try:
            self.conn.close()
        except Exception as e:
            logger.warning("EPS CCP: close failed: %s", e)
        self.conn = None

    # -- low level --------------------------------------------------------
    def _send(self, data):
        """Send an 8-byte CCP command frame to the CRO id (zero-padded)."""
        frame = bytes(data).ljust(8, b"\x00")[:8]
        self.conn.raw_send(self.cro_id, frame, extended=True)

    def connect(self):
        """Send CONNECT (sets the channel-enable bit). No reply is required to
        have arrived yet; discover_dto() waits for it."""
        self._send([CMD_CONNECT])

    def set_mta(self, addr, bank=0):
        """Set the Memory Transfer Address. Layout: F6 00 00 <bank> <addr LE32>."""
        self._send(
            [CMD_SET_MTA, 0x00, 0x00, bank & 0xFF] + list(addr.to_bytes(4, "little"))
        )

    # -- DTO discovery ----------------------------------------------------
    def discover_dto(self, timeout=2.0, retries=4):
        """Send CONNECT and learn the ECU's reply (DTO) id from the first reply
        frame. The DTO id is whatever id carries a frame with a leading status
        byte (0xFF/0xFE) that is NOT our own CRO id. Never hardcoded."""
        for attempt in range(retries):
            self.conn.drain_rawrxqueue()
            self.connect()
            deadline = time.time() + timeout
            while time.time() < deadline:
                frame = self.conn.raw_wait_frame(
                    timeout=max(0.05, min(0.5, deadline - time.time()))
                )
                if frame is None:
                    continue
                arb_id, _extended, fdata = frame
                if arb_id == self.cro_id:
                    continue  # our own frame echoed back (if the bus loops it)
                if fdata and fdata[0] in (STATUS_OK, STATUS_ERR):
                    self.dto_id = arb_id
                    logger.info("EPS CCP: discovered DTO reply id 0x%X", arb_id)
                    return arb_id
            logger.warning(
                "EPS CCP: no CONNECT reply (attempt %d/%d)", attempt + 1, retries
            )
        raise EpsCcpError(
            "no reply to CONNECT on CRO id 0x%X; DTO id not discovered. "
            "Check ignition, bus routing, and that the dongle is in raw mode."
            % self.cro_id
        )

    # -- reads ------------------------------------------------------------
    def _read_reply_bytes(self, nbytes, timeout, frame_timeout):
        """Collect reply frames from the DTO id until nbytes payload bytes are
        gathered. Honours the per-frame status byte and short final DLC."""
        collected = bytearray()
        deadline = time.time() + timeout
        while len(collected) < nbytes:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    "timed out collecting EPS reply (got %d/%d bytes)"
                    % (len(collected), nbytes)
                )
            frame = self.conn.raw_wait_frame(timeout=min(frame_timeout, remaining))
            if frame is None:
                continue
            arb_id, _extended, fdata = frame
            if arb_id != self.dto_id or not fdata:
                continue
            status = fdata[0]
            if status == STATUS_ERR:
                raise EpsCcpError("EPS CCP reply reported error status 0xFE")
            if status != STATUS_OK:
                continue  # not a CCP reply frame on this id; ignore
            payload = fdata[1:]
            take = min(len(payload), nbytes - len(collected))
            collected += payload[:take]
        return bytes(collected)

    def upload(self, nbytes, timeout=5.0, frame_timeout=1.0, settle=0.03):
        """UPLOAD nbytes from the current MTA (auto-incrementing) and return
        exactly nbytes.

        A CONNECT or SET-MTA ack can arrive a few ms after we drain, and since an
        ack frame carries the same leading 0xFF status byte as a data frame it
        would otherwise be mistaken for the first UPLOAD payload (off-by-N header
        corruption). So we drain, wait `settle` for any late ack to land, drain
        again, and only then issue UPLOAD."""
        self.conn.drain_rawrxqueue()
        if settle:
            time.sleep(settle)
            self.conn.drain_rawrxqueue()
        self._send([CMD_UPLOAD, nbytes & 0xFF])
        return self._read_reply_bytes(nbytes, timeout, frame_timeout)

    def dump(
        self,
        start=EPS_PARAM_START,
        length=EPS_PARAM_LENGTH,
        chunk=DEFAULT_UPLOAD_CHUNK,
        retries=3,
        upload_timeout=5.0,
        frame_timeout=1.0,
        progress=None,
    ):
        """Read `length` bytes from `start` and return them.

        Each chunk re-issues SET-MTA (so a failed chunk is independently
        retryable regardless of where the auto-incrementing MTA stopped), then
        UPLOADs up to `chunk` bytes. `progress`, if given, is called as
        progress(bytes_done, length)."""
        if self.dto_id is None:
            self.discover_dto()
        out = bytearray()
        pos = start
        end = start + length
        while pos < end:
            n = min(chunk, end - pos)
            last_err = None
            for attempt in range(retries):
                try:
                    self.set_mta(pos)
                    data = self.upload(
                        n, timeout=upload_timeout, frame_timeout=frame_timeout
                    )
                    if len(data) != n:
                        raise EpsCcpError(
                            "short read %d/%d at 0x%X" % (len(data), n, pos)
                        )
                    out += data
                    pos += n
                    if progress is not None:
                        progress(pos - start, length)
                    break
                except (TimeoutError, EpsCcpError) as e:
                    last_err = e
                    logger.warning(
                        "EPS CCP: read @0x%X attempt %d/%d failed: %s",
                        pos,
                        attempt + 1,
                        retries,
                        e,
                    )
                    # Resync the channel before retrying this chunk.
                    time.sleep(0.1)
                    self.connect()
                    time.sleep(0.05)
            else:
                raise EpsCcpError(
                    "failed to read 0x%X after %d retries: %s"
                    % (pos, retries, last_err)
                )
        return bytes(out)

    def sniff(self, seconds=5.0):
        """Enter (already entered in open()), send CONNECT and collect every raw
        CAN frame seen for `seconds`. Returns a list of (arb_id, extended,
        data)."""
        self.conn.drain_rawrxqueue()
        self.connect()
        frames = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            remaining = deadline - time.time()
            frame = self.conn.raw_wait_frame(timeout=max(0.05, min(0.5, remaining)))
            if frame is not None:
                frames.append(frame)
        return frames


# --------------------------------------------------------------------------
# Module-level convenience wrappers (used by the CLI and GUI).
# --------------------------------------------------------------------------
def dump_eps_parametrization(
    interface,
    start=EPS_PARAM_START,
    length=EPS_PARAM_LENGTH,
    cro_id=EPS_CRO_ID,
    interface_path=None,
    upload_chunk=DEFAULT_UPLOAD_CHUNK,
    progress=None,
):
    """Open the BLE raw channel, CONNECT, discover the DTO id, dump
    [start, start+length) and return the bytes. Always exits raw mode / closes
    the connection on the way out."""
    ch = EpsCcpChannel(interface, cro_id=cro_id, interface_path=interface_path)
    ch.open()
    try:
        ch.discover_dto()
        return ch.dump(
            start=start, length=length, chunk=upload_chunk, progress=progress
        )
    finally:
        ch.close()


def sniff_ccp(interface, seconds=5.0, cro_id=EPS_CRO_ID, interface_path=None):
    """Open the BLE raw channel, send CONNECT and return every observed raw CAN
    frame for `seconds` as a list of (arb_id, extended, data)."""
    ch = EpsCcpChannel(interface, cro_id=cro_id, interface_path=interface_path)
    ch.open()
    try:
        return ch.sniff(seconds=seconds)
    finally:
        ch.close()
