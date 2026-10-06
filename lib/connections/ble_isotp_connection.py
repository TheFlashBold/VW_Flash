from udsoncan.connections import BaseConnection

from bleak import BleakClient
from bleak import BleakScanner

import logging
import queue
import threading
import asyncio

# Dedicated logger for raw ISO-TP/UDS frames crossing the BLE bridge. The GUI
# attaches a handler to show these live; they also go to the normal log files.
frame_logger = logging.getLogger("CANFrames")

# --- RAW CAN MODE (esp32-isotp-ble-bridge, see RAW_CAN_MODE.md) -------------
# Additive, opt-in mode of the bridge. It reuses the SAME 8-byte BLE header;
# only cmdFlags (byte[1]) and the payload change. Used to talk to non-ISO-TP
# channels such as the VW EPS proprietary CCP/XCP-on-CAN measurement channel.
BLE_COMMAND_FLAG_RAW = 0x10  # cmdFlags: raw CAN frame in payload
BLE_COMMAND_FLAG_SETTINGS = 0x80  # cmdFlags: settings SET
BRG_SETTING_RAW_MODE = 9  # setting id to enter/exit raw mode
RAW_CAN_FLAG_EXTENDED = 0x01  # rawFlags bit0: 29-bit extended arbitration id

_UDS_SID = {
    0x10: "DiagSessionControl", 0x11: "ECUReset", 0x14: "ClearDTC",
    0x19: "ReadDTC", 0x22: "ReadDataByIdentifier", 0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess", 0x28: "CommControl", 0x2E: "WriteDataByIdentifier",
    0x2F: "IOControl", 0x31: "RoutineControl", 0x34: "RequestDownload",
    0x35: "RequestUpload", 0x36: "TransferData", 0x37: "TransferExit",
    0x3E: "TesterPresent", 0x85: "ControlDTCSetting",
}
_UDS_NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported", 0x13: "incorrectLength",
    0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
    0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x78: "responsePending", 0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def _decode_uds(p: bytes) -> str:
    if not p:
        return "(empty)"
    sid = p[0]
    if sid == 0x7F and len(p) >= 3:
        return "NegResp to 0x%02X, NRC 0x%02X %s" % (
            p[1], p[2], _UDS_NRC.get(p[2], "?")
        )
    if sid >= 0x40 and (sid - 0x40) in _UDS_SID:
        extra = ""
        if sid == 0x62 and len(p) >= 3:
            extra = " DID 0x%02X%02X" % (p[1], p[2])
        return "PosResp %s%s" % (_UDS_SID[sid - 0x40], extra)
    if sid in _UDS_SID:
        extra = ""
        if sid == 0x22 and len(p) >= 3:
            extra = " DID 0x%02X%02X" % (p[1], p[2])
        elif sid == 0x10 and len(p) >= 2:
            extra = " session 0x%02X" % p[1]
        return "Req %s%s" % (_UDS_SID[sid], extra)
    return "SID 0x%02X" % sid


class BLEISOTPConnection(BaseConnection):
    def __init__(
        self,
        ble_service_uuid,
        ble_notify_uuid,
        ble_write_uuid,
        interface_name,
        rxid,
        txid,
        name=None,
        debug=False,
        device_address=None,
        tx_stmin=None,
        dq3xx_hack=False,
        *args,
        **kwargs
    ):

        BaseConnection.__init__(self, name)
        self.txid = txid
        self.rxid = rxid
        self.tx_stmin = tx_stmin

        # Set up the ble specific propertires
        self.ble_service_uuid = ble_service_uuid
        self.ble_notify_uuid = ble_notify_uuid
        self.ble_write_uuid = ble_write_uuid
        self.interface_name = interface_name
        self.client = None
        self.payload = None
        self.device = None
        self.device_address = device_address
        self.dq3xx_hack = dq3xx_hack

        # print out debug stuff
        self.logger.debug(
            "BLE connection info: "
            + "NOTIFY_UUID: "
            + str(self.ble_notify_uuid)
            + ", WRITE_UUID: "
            + str(self.ble_write_uuid)
            + ", RXID: "
            + str(hex(self.rxid))
            + ", TXID: "
            + str(hex(self.txid))
            + ", TX STMin (usec): "
            + str(self.tx_stmin)
        )

        self.rxqueue = queue.Queue()
        # Raw CAN mode state. While raw_mode is on, incoming notifications are
        # parsed as raw CAN frames (arb_id, extended, data) onto rawrxqueue
        # instead of the ISO-TP rxqueue. Off by default -> ISO-TP behaviour is
        # completely untouched.
        self.raw_mode = False
        self.rawrxqueue = queue.Queue()
        # We take this lock to wait on the main thread for the asyncio/coroutine thread to finish opening up the device.
        self.connection_open_lock = threading.Condition()
        self.exit_requested = False
        self.opened = False

    async def scan_for_ble_devices(self, interface_name, interface_address=None):
        # Get ble devices, we'll go through each one until we find one that
        #  matches the interface_name
        #  await will pause until it's done

        # we'll try a couple times to scan (since the bridge can go dark
        # if it was recently used and disconncted from)
        for i in range(8):
            self.logger.info("Scanning for BLE bridge, attempt number: " + str(i))
            devices = await BleakScanner.discover(service_uuids=[self.ble_service_uuid])

            for d in devices:
                self.logger.debug("Found: " + str(d))
                if interface_address is not None and d.address == interface_address:
                    return d
                elif d.name == interface_name:
                    return d
            self.logger.info("BLE device not found, waiting")
            await asyncio.sleep(10)
        return None

    async def set_device_value(self, value_id, payload):
        cmd = bytes([value_id + 0x80])
        await self.send_command_packet(cmd, payload)

    async def send_command_packet(self, cmd, payload):
        cmd_payload = (
            b"\xF1"
            + cmd
            + self.rxid.to_bytes(2, "little")
            + self.txid.to_bytes(2, "little")
            + len(payload).to_bytes(2, "little")
            + payload
        )
        self.logger.debug("Sending a command packet: " + cmd_payload.hex())
        await self.client.write_gatt_char(self.ble_write_uuid, cmd_payload)

    async def setup(self):
        self.txqueue = asyncio.Queue()
        if self.device is None:
            self.logger.debug(
                "No device set. Attempting to open a connection to: "
                + str(self.device_address)
            )
            self.device = await self.scan_for_ble_devices(
                self.interface_name, interface_address=self.device_address
            )

        # Define the BleakClient, and then wait while we connect to it
        self.client = BleakClient(self.device)
        await self.client.connect()

        # Once we've gotten this close - we should be connected to it
        # Start the notify for our rx characteristic. Callback should be to a local function that
        #  will stick the response in our rxqueue
        await self.client.start_notify(self.ble_notify_uuid, self.notification_handler)
        self.logger.debug(
            "BLE_ISOTP start_notify for uuid: "
            + str(self.ble_notify_uuid)
            + " with callback "
            + str(self.notification_handler)
        )

        # This is our txthread, we'll log some things as it's set up and then enter the main
        # loop
        self.logger.debug("Starting thread for ble client connection")
        self.exit_requested = False

        # set the opened variable so data can start to be sent
        self.opened = True
        self.logger.info("BLE_ISOTP Connection opened to: " + str(self.device_address))

        # override the TRANSMIT STMin. This is the STMin which is used to space out message transmissions, NOT the stmin we send to the ISO-TP partner.
        # F1 -> Header, 0x20 -> "Set TX_STMIN", rxid, txid, size of command (2),
        if self.tx_stmin is not None:
            stmin = self.tx_stmin.to_bytes(2, "little")
            await self.set_device_value(0x1, stmin)

        if self.dq3xx_hack:
            await self.set_device_value(0x9, int(self.dq3xx_hack).to_bytes(2, "little"))

        with self.connection_open_lock:
            self.connection_open_lock.notifyAll()
        # main tx loop
        while True:
            # If we've been asked to exit, exit
            if self.exit_requested:
                return self
            # if there's a payload that needs to be sent, write it
            payload: bytes = await self.txqueue.get()
            self.logger.debug(
                "Sending payload via write_gatt_char to: "
                + str(self.ble_write_uuid)
                + " - "
                + str(payload.hex())
            )
            await self.client.write_gatt_char(self.ble_write_uuid, payload)
            self.logger.debug("Sent payload via write_gatt")

    async def disconnect(self):
        self.logger.info("Exit requested from BLEISOTP loop")
        await self.client.stop_notify(self.ble_notify_uuid)
        self.logger.debug("stopped notify")
        await self.client.disconnect()
        self.logger.debug("Disconnected from client")
        self.opened = False
        self.logger.debug("Set opened flag to False")

    def asyncio_thread(self):
        self.txloop = asyncio.new_event_loop()
        self.txloop.set_debug(True)
        asyncio.set_event_loop(self.txloop)
        asyncio.run_coroutine_threadsafe(self.setup(), self.txloop)
        self.txloop.run_forever()

    def open(self):
        self.logger.debug("ble open function called")
        self.txthread = threading.Thread(target=self.asyncio_thread)
        self.txthread.daemon = True
        self.txthread.start()

        self.logger.debug("Waiting for ble connection to be established")
        with self.connection_open_lock:
            self.connection_open_lock.wait_for(self.is_open)

        return

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        asyncio.run(self.asyncio_close())

    def is_open(self):
        return self.opened

    @staticmethod
    def _parse_raw_notification(raw: bytes):
        """Split a (possibly coalesced) BLE notification into raw CAN frames.

        The bridge may pack several raw-RX frames into one notification via its
        multi-send logic; each is a complete 8-byte header + payload block.
        Returns a list of (arb_id, extended, data) tuples for RAW blocks.
        """
        frames = []
        offset = 0
        n = len(raw)
        while offset + 8 <= n:
            if raw[offset] != 0xF1:
                break
            cmd_flags = raw[offset + 1]
            size = int.from_bytes(raw[offset + 6 : offset + 8], "little")
            payload = raw[offset + 8 : offset + 8 + size]
            if len(payload) < size:
                break
            offset += 8 + size
            if (cmd_flags & BLE_COMMAND_FLAG_RAW) and len(payload) >= 6:
                raw_flags = payload[0]
                dlc = payload[1]
                arb_id = int.from_bytes(payload[2:6], "little")
                frame_data = bytes(payload[6 : 6 + dlc])
                extended = bool(raw_flags & RAW_CAN_FLAG_EXTENDED)
                frames.append((arb_id, extended, frame_data))
        return frames

    def notification_handler(self, sender, data):
        raw = bytes(data)
        if self.raw_mode:
            for arb_id, extended, frame_data in self._parse_raw_notification(raw):
                frame_logger.info(
                    "RX  RAW CAN 0x%X %s %s"
                    % (arb_id, "EXT" if extended else "STD", frame_data.hex())
                )
                self.rawrxqueue.put((arb_id, extended, frame_data))
            return
        payload = raw[8:]
        frame_logger.info("RX  BLE raw %s" % raw.hex())
        frame_logger.info(
            "RX  CAN 0x%03X  UDS %s  [%s]"
            % (self.rxid, payload.hex(), _decode_uds(payload))
        )
        self.logger.debug(
            "Received callback from notify: " + str(sender) + " - " + str(data)
        )
        self.rxqueue.put(data[8:])

    def close(self):
        self.exit_requested = True
        asyncio.run_coroutine_threadsafe(self.disconnect(), self.txloop)
        self.logger.info("BLE_ISOTP Connection closed")

    def specific_send(self, payload):
        frame_logger.info(
            "TX  CAN 0x%03X  UDS %s  [%s]"
            % (self.txid, bytes(payload).hex(), _decode_uds(bytes(payload)))
        )
        self.logger.debug("TXID: " + str(self.txid.to_bytes(2, "little")))
        self.logger.debug("RXID: " + str(self.rxid.to_bytes(2, "little")))

        header = (
            b"\xF1\x00"
            + self.rxid.to_bytes(2, "little")
            + self.txid.to_bytes(2, "little")
            + len(payload).to_bytes(2, "little")
        )

        self.logger.debug(header)
        payload = header + payload

        self.logger.debug("[specific_send] - Sending payload: " + str(payload.hex()))
        self.logger.debug(
            "[specific-send] - TOTAL payload length is: " + str(len(payload))
        )

        if len(payload) > 0x150:
            payload = b"\xF1\x08" + payload[2:]
            sequence = 0

            self.logger.debug(
                "[specific-send] - Breaking payload into smaller chunks for multiframe send"
            )
            while len(payload) > 0:
                if sequence == 0:
                    asyncio.run_coroutine_threadsafe(
                        self.txqueue.put(payload[0:0x150]), self.txloop
                    )
                    payload = payload[0x150:]
                    sequence += 1
                else:
                    self.logger.debug(
                        "[specific_send] - multiframe_queue size: "
                        + str(self.txqueue.qsize())
                    )
                    asyncio.run_coroutine_threadsafe(
                        self.txqueue.put(
                            b"\xF2"
                            + sequence.to_bytes(1, "little")
                            + payload[0 : 0x150 - 2]
                        ),
                        self.txloop,
                    )
                    sequence += 1
                    payload = payload[0x150 - 2 :]

            self.logger.debug("Done enqueuing multiframe payload")
            return

        else:
            asyncio.run_coroutine_threadsafe(self.txqueue.put(payload), self.txloop)

    async def async_wait_frame(self, timeout=4):
        self.logger.debug("In async wait_frame")
        frame = None
        while frame is None:
            frame = self.rxqueue.get(timeout=timeout)

        return frame

    def specific_wait_frame(self, timeout=4):
        timeout = 10
        if not self.opened:
            raise RuntimeError("BLE_ISOTP Connection is not open")
        try:
            frame = self.rxqueue.get(block=True, timeout=timeout)
        except:
            frame = None
        return frame

    async def async_empty_rxqueue(self):
        # rxqueue = self.rxqueue.get()
        # rxqueue.empty()
        return

    def empty_rxqueue(self):
        asyncio.run(self.async_empty_rxqueue())

    # --- RAW CAN MODE helpers ------------------------------------------------
    # These are isolated from the ISO-TP path: they only run while raw mode is
    # enabled (via enter_raw_mode) and use a dedicated rawrxqueue. Turning raw
    # mode off restores normal ISO-TP behaviour.

    def enter_raw_mode(self, timeout=5):
        """Tell the bridge to enter raw CAN mode (setting 9 = 0x01) and route
        incoming notifications to the raw RX queue. Blocks until the settings
        packet has been written."""
        self.drain_rawrxqueue()
        self.raw_mode = True
        fut = asyncio.run_coroutine_threadsafe(
            self.send_command_packet(
                bytes([BLE_COMMAND_FLAG_SETTINGS | BRG_SETTING_RAW_MODE]), b"\x01"
            ),
            self.txloop,
        )
        fut.result(timeout=timeout)
        self.logger.info("Entered RAW CAN mode")

    def exit_raw_mode(self, timeout=5):
        """Tell the bridge to leave raw CAN mode (setting 9 = 0x00) and resume
        normal ISO-TP routing."""
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self.send_command_packet(
                    bytes([BLE_COMMAND_FLAG_SETTINGS | BRG_SETTING_RAW_MODE]), b"\x00"
                ),
                self.txloop,
            )
            fut.result(timeout=timeout)
        finally:
            self.raw_mode = False
            self.logger.info("Exited RAW CAN mode")

    def raw_send(self, arb_id: int, data: bytes, extended: bool = True):
        """Transmit a single raw CAN frame. data is 0..8 bytes; DLC = len(data).
        Only valid while raw mode is enabled on the bridge."""
        data = bytes(data)
        dlc = len(data)
        raw_flags = RAW_CAN_FLAG_EXTENDED if extended else 0x00
        payload = bytes([raw_flags, dlc]) + arb_id.to_bytes(4, "little") + data
        packet = (
            b"\xF1"
            + bytes([BLE_COMMAND_FLAG_RAW])
            + (0).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
            + len(payload).to_bytes(2, "little")
            + payload
        )
        frame_logger.info(
            "TX  RAW CAN 0x%X %s %s"
            % (arb_id, "EXT" if extended else "STD", data.hex())
        )
        asyncio.run_coroutine_threadsafe(self.txqueue.put(packet), self.txloop)

    def raw_wait_frame(self, timeout=1.0):
        """Pop one raw CAN frame (arb_id, extended, data) or None on timeout."""
        try:
            return self.rawrxqueue.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

    def drain_rawrxqueue(self):
        """Discard any buffered raw RX frames."""
        try:
            while True:
                self.rawrxqueue.get_nowait()
        except queue.Empty:
            pass
