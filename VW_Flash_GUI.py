import asyncio
import glob
from pathlib import Path
import wx
import os.path as path
import os
import logging
import json
import threading
import sys
import serial
import serial.tools.list_ports

from zipfile import ZipFile
from datetime import datetime

from lib import extract_flash, haldex_binfile
from lib import binfile
from lib import flash_uds
from lib import simos_flash_utils
from lib import dsg_flash_utils
from lib import dq381_flash_utils
from lib import haldex_flash_utils
from lib import eps_flash_utils
from lib import eps_ccp
from lib import constants
from lib import simos_hsl

from lib.modules import (
    simos8,
    simos10,
    simos12,
    simos122,
    simos18,
    simos1810,
    simos184,
    dq250mqb,
    dq381,
    dq400mqb,
    dq500_0bh,
    dq500_0dl,
    simos16,
    haldex4motion,
    eps_mqb,
    gateway_mqb,
)

DEFAULT_STMIN = 350000

if sys.platform == "win32":
    try:
        import winreg
    except ModuleNotFoundError:
        print("module winreg not found")

# Get an instance of logger, which we'll pull from the config file
logger = logging.getLogger("VWFlash")


def show_error_dialog(exc_type, exc_value):
    dlg = wx.MessageDialog(
        None,
        f"A Python exception occured: {exc_type}, {exc_value}. Please check the log file.",
        "Error!",
        wx.OK | wx.ICON_ERROR | wx.CENTRE,
    )
    dlg.ShowModal()
    dlg.Destroy()


def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    wx.CallAfter(show_error_dialog, exc_type, exc_value)
    wx.CallAfter(wx.Exit)


def handle_threaded_exception(args, /):
    (exc_type, exc_value, exc_traceback, thread) = args
    handle_exception(exc_type, exc_value, exc_traceback)


sys.excepthook = handle_exception
threading.excepthook = handle_threaded_exception

try:
    currentPath = getattr(sys, "_MEIPASS", path.dirname(path.abspath(__file__)))
except NameError:  # We are the main py2exe script, not a module
    currentPath = path.dirname(path.abspath(sys.argv[0]))

if sys.platform == "darwin":
    appDataPath = path.join(
        path.expanduser("~"), "Library", "Application Support", "VW_Flash"
    )
else:
    appDataPath = currentPath
configPath = path.join(appDataPath, "gui_config.json")
logPath = path.join(appDataPath, "logs")
os.makedirs(logPath, exist_ok=True)
os.chdir(appDataPath)

logging.config.fileConfig(path.join(currentPath, "logging.conf"))


def write_config(paths):
    with open(configPath, "w") as config_file:
        json.dump(paths, config_file)


class FeedbackLogHandler(logging.Handler):
    """Routes raw-frame log records (logger "CANFrames") into a wx TextCtrl so the
    operator can watch the ISO-TP/UDS frames live, in addition to the log file."""

    def __init__(self, text_ctrl):
        super().__init__()
        self.text_ctrl = text_ctrl
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            msg = self.format(record)
        except Exception:
            return
        wx.CallAfter(self.text_ctrl.AppendText, msg + "\n")


def module_selection_is_dq250(selection_index):
    return selection_index == 2


def module_selection_is_dq381(selection_index):
    return selection_index == 3


def module_selection_is_dq400(selection_index):
    return selection_index == 4


def module_selection_is_dq500(selection_index):
    return selection_index == 5


def module_selection_is_dq500_0dl(selection_index):
    return selection_index == 6


def module_selection_is_haldex(selected_index):
    return selected_index == 7


def module_selection_is_eps(selection_index):
    return selection_index == 8


def module_selection_is_gateway(selection_index):
    return selection_index == 9


def module_selection_is_dsg(selection_index):
    return (
        module_selection_is_dq250(selection_index)
        or module_selection_is_dq381(selection_index)
        or module_selection_is_dq400(selection_index)
        or module_selection_is_dq500(selection_index)
        or module_selection_is_dq500_0dl(selection_index)
    )


def split_interface_name(interface_string: str):
    parts = interface_string.split("_", 1)
    interface = parts[0]
    interface_name = parts[1] if len(parts) > 1 else None
    return (interface, interface_name)


async def async_scan_for_ble_devices():
    interfaces = []
    try:
        # We have to import this from the correct thread. No joke.
        from bleak import BleakScanner

        devices = await BleakScanner.discover(
            service_uuids=[constants.BLE_SERVICE_IDENTIFIER]
        )
    except:
        return interfaces
    for d in devices:
        interfaces.append((d.name, "BLEISOTP_" + d.address))
    return interfaces


def scan_for_ble_devices(callback):
    threading.Thread(
        target=lambda cb: cb(asyncio.run(async_scan_for_ble_devices())), args=[callback]
    ).start()


def get_dlls_from_registry():
    # Interfaces is a list of tuples (name: str, interface specifier: str)
    interfaces = []
    try:
        BaseKey = winreg.OpenKeyEx(
            winreg.HKEY_LOCAL_MACHINE, r"Software\\PassThruSupport.04.04\\"
        )
    except OSError:
        logger.error("No J2534 DLLs found in HKLM PassThruSupport. Continuing anyway.")
        return interfaces

    for i in range(winreg.QueryInfoKey(BaseKey)[0]):
        try:
            DeviceKey = winreg.OpenKeyEx(BaseKey, winreg.EnumKey(BaseKey, i))
            Name = winreg.QueryValueEx(DeviceKey, "Name")[0]
            FunctionLibrary = winreg.QueryValueEx(DeviceKey, "FunctionLibrary")[0]
            interfaces.append((Name, "J2534_" + FunctionLibrary))
        except OSError:
            logger.error(
                "Found a J2534 interface, but could not enumerate the registry entry. Continuing."
            )
    return interfaces


def socketcan_ports():
    return [("SocketCAN can0", "SocketCAN_can0")]


def poll_interfaces():
    # this is a list of tuples (name: str, interface_specifier: str) where interface_specifier is something like USBISOTP_/dev/ttyUSB0
    interfaces = []

    if sys.platform == "win32":
        interfaces += get_dlls_from_registry()
    if sys.platform == "linux":
        interfaces += socketcan_ports()

    serial_ports = serial.tools.list_ports.comports()
    for port in serial_ports:
        interfaces.append(
            (port.name + " : " + port.description, "USBISOTP_" + port.device)
        )
    return interfaces


class UnlockDialog(wx.Dialog):
    def __init__(self, parent, title):
        super(UnlockDialog, self).__init__(parent, title=title, size=(500, 120))
        self.parent = parent
        # Setup panel & sizers
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.AddSpacer(5)
        # Setup UI elements
        self.file_picker = wx.FilePickerCtrl(panel, wildcard="*.frf")
        self.flash_button = wx.Button(panel, wx.ID_OK, label="Unlock ECU")
        self.cancel_button = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        # Add elements to sizers
        button_sizer.Add(self.flash_button)
        button_sizer.Add(self.cancel_button, flag=wx.LEFT)
        sizer.Add(self.file_picker, flag=wx.EXPAND | wx.LEFT | wx.RIGHT, border=5)
        sizer.Add(button_sizer, flag=wx.ALIGN_CENTER | wx.TOP, border=5)
        panel.SetSizer(sizer)
        # Bind button clicks
        self.flash_button.Bind(wx.EVT_BUTTON, self.on_button)
        self.cancel_button.Bind(wx.EVT_BUTTON, self.on_button)

    def on_button(self, event):
        if self.IsModal():
            if event.EventObject.Id == wx.ID_OK:
                self.parent.selected_unlock = self.file_picker.GetPath()
                self.EndModal(1)
            else:
                self.EndModal(-1)
        else:
            self.Close()


class StminDialog(wx.Dialog):
    def __init__(self, parent, title, currentValue):
        super(StminDialog, self).__init__(parent, title=title, size=(300, 120))
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.slider = wx.Slider(
            panel, value=currentValue // 1000, minValue=0, maxValue=1000
        )
        self.label = wx.StaticText(panel, label=str(currentValue // 1000))
        self.ok_btn = wx.Button(panel, wx.ID_OK, label="Save")
        self.cancel_btn = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        button_sizer.Add(self.ok_btn)
        button_sizer.Add(self.cancel_btn, flag=wx.Left)
        sizer.Add(self.slider, flag=wx.EXPAND | wx.LEFT | wx.RIGHT)
        sizer.Add(self.label, flag=wx.ALIGN_CENTER)
        sizer.Add(button_sizer, flag=wx.ALIGN_RIGHT | wx.BOTTOM)
        panel.SetSizer(sizer)
        self.ok_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.slider.Bind(wx.EVT_SLIDER, self.on_slider)

    def on_slider(self, event):
        self.label.SetLabelText(str(self.slider.GetValue()))

    def on_button(self, event):
        if self.IsModal():
            if event.EventObject.Id == wx.ID_OK:
                self.EndModal(self.slider.GetValue() * 1000)
            else:
                self.EndModal(-1)
        else:
            self.Close()


class EpsIdsDialog(wx.Dialog):
    def __init__(self, parent, title, tx_hex: str, rx_hex: str):
        super(EpsIdsDialog, self).__init__(parent, title=title, size=(320, 180))
        panel = wx.Panel(self)
        sizer = wx.BoxSizer(wx.VERTICAL)
        grid = wx.FlexGridSizer(2, 2, 5, 5)
        self.tx_ctrl = wx.TextCtrl(panel, value=tx_hex)
        self.rx_ctrl = wx.TextCtrl(panel, value=rx_hex)
        grid.Add(wx.StaticText(panel, label="Request ID (tx):"), 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.tx_ctrl, 1, wx.EXPAND)
        grid.Add(wx.StaticText(panel, label="Response ID (rx):"), 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.rx_ctrl, 1, wx.EXPAND)
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.ok_btn = wx.Button(panel, wx.ID_OK, label="Save")
        self.cancel_btn = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        button_sizer.Add(self.ok_btn)
        button_sizer.Add(self.cancel_btn, flag=wx.LEFT, border=5)
        sizer.Add(grid, flag=wx.EXPAND | wx.ALL, border=10)
        sizer.Add(button_sizer, flag=wx.ALIGN_RIGHT | wx.ALL, border=5)
        panel.SetSizer(sizer)
        self.ok_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.cancel_btn.Bind(wx.EVT_BUTTON, self.on_button)
        self.result = None

    def on_button(self, event):
        if self.IsModal():
            if event.EventObject.Id == wx.ID_OK:
                try:
                    tx = int(self.tx_ctrl.GetValue().strip(), 16)
                    rx = int(self.rx_ctrl.GetValue().strip(), 16)
                except ValueError:
                    wx.MessageDialog(
                        self,
                        "IDs must be hex, e.g. 0x712 / 0x77C.",
                        "Invalid ID",
                        wx.OK | wx.ICON_ERROR,
                    ).ShowModal()
                    return
                self.result = ("0x%03X" % tx, "0x%03X" % rx)
                self.EndModal(wx.ID_OK)
            else:
                self.EndModal(wx.ID_CANCEL)
        else:
            self.Close()


class FlashPanel(wx.Panel):
    input_blocks: dict[str, constants.BlockData]

    def __init__(self, parent):
        super().__init__(parent)

        try:
            with open(configPath, "r") as config_file:
                self.options = json.load(config_file)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("Configuration was missing or invalid. Creating...")
            self.options = {
                "cal": "",
                "flashpack": "",
                "bins": "",
                "logger": logPath,
                "interface": "",
                "singlecsv": False,
                "scanble": False,
                "logmode": "22",
                "activitylevel": "INFO",
                "eps_txid": "0x712",
                "eps_rxid": "0x77C",
                "showframes": False,
            }
            write_config(self.options)

        self.interfaces = poll_interfaces()

        # Pick first interface if none already selected.
        if (len(self.options["interface"])) == 0:
            if len(self.interfaces) > 0:
                self.options["interface"] = self.interfaces[0][1]
                write_config(self.options)

        main_sizer = wx.BoxSizer(wx.VERTICAL)
        folder_sizer = wx.BoxSizer(wx.HORIZONTAL)
        # WrapSizer so the action buttons wrap to the next line on narrow windows
        # instead of being clipped.
        actions_sizer = wx.WrapSizer(wx.HORIZONTAL)
        selections_sizer = wx.BoxSizer(wx.HORIZONTAL)

        # Create a drop down menu

        self.flash_info = simos18.s18_flash_info
        self.binfile_handler = binfile.BinFileHandler(self.flash_info)
        available_modules = [
            "Simos 18.1/6",
            "Simos 18.10",
            "DQ250-MQB DSG",
            "DQ381 DSG",
            "DQ400-MQB DSG",
            "DQ500-0BH DSG",
            "DQ500-0DL DSG",
            "Haldex (4motion) UNTESTED",
            "EPS MQB (ZF) UNTESTED",
            "Gateway MQB (Get Info only)",
        ]
        self.module_choice = wx.Choice(self, choices=available_modules)
        self.module_choice.SetSelection(0)
        self.module_choice.Bind(wx.EVT_CHOICE, self.on_module_changed)

        available_actions = [
            "Calibration Flash Unlocked",
            "FlashPack ZIP flash",
            "Full Flash Unlocked (BIN/FRF)",
            "Flash Stock (Re-Lock) / Unmodified BIN/FRF",
        ]
        self.action_choice = wx.Choice(self, choices=available_actions)
        self.action_choice.SetSelection(0)
        self.action_choice.Bind(wx.EVT_CHOICE, self.update_bin_listing)

        # Create a button for choosing the folder
        self.folder_button = wx.Button(self, label="Open Folder...")
        self.folder_button.Bind(wx.EVT_BUTTON, self.GetParent().on_open_folder)

        folder_sizer.Add(self.folder_button, 0, wx.ALL | wx.LEFT, 5)

        self.progress_bar = wx.Gauge(self, range=100, style=wx.GA_HORIZONTAL)

        self.row_obj_dict = {}

        self.list_ctrl = wx.ListCtrl(
            self,
            size=(-1, 140),
            style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SINGLE_SEL,
        )
        self.list_ctrl.InsertColumn(0, "Filename", width=400)
        self.list_ctrl.InsertColumn(1, "Modify time", width=100)

        self.list_ctrl.Bind(
            wx.EVT_LIST_ITEM_SELECTED, lambda evt: self.set_item_style(evt, True)
        )
        self.list_ctrl.Bind(
            wx.EVT_LIST_ITEM_DESELECTED, lambda evt: self.set_item_style(evt, False)
        )

        self.feedback_text = wx.TextCtrl(
            self, size=(-1, 160), style=wx.TE_READONLY | wx.TE_LEFT | wx.TE_MULTILINE
        )

        flash_button = wx.Button(self, label="Flash")
        flash_button.Bind(wx.EVT_BUTTON, self.on_flash)

        dtc_button = wx.Button(self, label="Read Trouble Codes")
        dtc_button.Bind(wx.EVT_BUTTON, self.on_read_dtcs)

        get_info_button = wx.Button(self, label="Get Ecu Info")
        get_info_button.Bind(wx.EVT_BUTTON, self.on_get_info)

        # EPS-only buttons: read the live parametrization over the raw-CAN CCP
        # channel. Shown only while the EPS MQB module is selected (see
        # apply_module_buttons()). (The old 0x35 "Dump ECU" button was removed:
        # the bootloader upload is state-gated and returns 0x31 on intact blocks.)
        self.dump_ccp_button = wx.Button(self, label="Dump EPS (CCP)")
        self.dump_ccp_button.Bind(wx.EVT_BUTTON, self.on_dump_ccp)

        self.sniff_ccp_button = wx.Button(self, label="Sniff EPS (CCP)")
        self.sniff_ccp_button.Bind(wx.EVT_BUTTON, self.on_sniff_ccp)

        actions_sizer.Add(self.module_choice, 0, wx.LEFT, 5)
        actions_sizer.Add(get_info_button, 0, wx.LEFT | wx.RIGHT, 5)
        actions_sizer.Add(dtc_button, 0, wx.RIGHT, 5)
        actions_sizer.Add(self.dump_ccp_button, 0, wx.RIGHT, 5)
        actions_sizer.Add(self.sniff_ccp_button, 0, wx.RIGHT, 5)

        # action_choice fills the width; the Flash button keeps its size.
        selections_sizer.Add(self.action_choice, 1, wx.EXPAND | wx.ALL, 5)
        selections_sizer.Add(flash_button, 0, wx.ALL, 5)

        # Vertical layout: the log (feedback_text) and the file list both grow
        # with the window (proportion > 0 + EXPAND); the button/choice/progress
        # rows keep their height but expand horizontally.
        main_sizer.Add(self.feedback_text, 2, wx.ALL | wx.EXPAND, 5)
        main_sizer.Add(actions_sizer, 0, wx.EXPAND | wx.TOP, 5)
        main_sizer.Add(folder_sizer, 0, wx.EXPAND, 5)
        main_sizer.Add(self.list_ctrl, 1, wx.ALL | wx.EXPAND, 5)
        main_sizer.Add(self.progress_bar, 0, wx.EXPAND | wx.ALL, 2)
        main_sizer.Add(selections_sizer, 0, wx.EXPAND)

        self.SetSizer(main_sizer)

        # Apply any saved EPS diagnostic ID overrides to the EPS flash_info.
        self.apply_eps_ids()

        # Show the EPS-only buttons only for the EPS module (default module is
        # not EPS, so they start hidden).
        self.apply_module_buttons()

        # Route raw ISO-TP/UDS frame logging into the feedback box. Toggle via
        # Interface -> "Show raw CAN frames".
        self.frame_log_handler = FeedbackLogHandler(self.feedback_text)
        self.frame_logger = logging.getLogger("CANFrames")
        self.frame_logger.setLevel(logging.INFO)
        self.apply_frame_logging(self.options.get("showframes", True))

        if self.options["cal"] != "":
            self.current_folder_path = self.options["cal"]
            self.update_bin_listing()

    def set_item_style(self, event, selected):
        self.list_ctrl.SetItemFont(
            event.GetIndex(), wx.Font(wx.FontInfo().Bold(selected))
        )

    def eps_ids(self):
        # (txid, rxid) the GUI uses for the EPS module. Firmware default is
        # tx 0x712 / rx 0x77C; overridable from the config (Interface menu) in
        # case the gateway on a given car diagnoses the module under other IDs.
        txid = int(str(self.options.get("eps_txid", "0x712")), 16)
        rxid = int(str(self.options.get("eps_rxid", "0x77C")), 16)
        return (txid, rxid)

    def apply_eps_ids(self):
        # Push the configured EPS diagnostic IDs onto the EPS flash_info so both
        # the dump and any flash use them.
        txid, rxid = self.eps_ids()
        eps_mqb.eps_flash_info.control_module_identifier = (
            constants.ControlModuleIdentifier(rxid, txid)
        )

    def apply_module_buttons(self):
        # Show the EPS-only buttons (Dump ECU, Dump/Sniff EPS CCP) only while the
        # EPS MQB module is selected; hide them for every other module.
        is_eps = module_selection_is_eps(self.module_choice.GetSelection())
        for btn in (self.dump_ccp_button, self.sniff_ccp_button):
            btn.Show(is_eps)
        self.Layout()

    def apply_frame_logging(self, enabled: bool):
        # Gate the frame logger entirely: when off, raise its level so nothing is
        # emitted to the window OR the log files (a RequestUpload dumps tens of
        # thousands of frames and would otherwise flood both).
        self.frame_logger.removeHandler(self.frame_log_handler)
        if enabled:
            self.frame_logger.setLevel(logging.INFO)
            self.frame_logger.addHandler(self.frame_log_handler)
        else:
            self.frame_logger.setLevel(logging.WARNING)

    def on_module_changed(self, event):
        module_number = self.module_choice.GetSelection()
        if module_selection_is_eps(module_number):
            self.apply_eps_ids()
        self.apply_module_buttons()
        self.flash_info = [
            simos18.s18_flash_info,
            simos1810.s1810_flash_info,
            dq250mqb.dsg_flash_info,
            dq381.dsg_flash_info,
            dq400mqb.dsg_flash_info,
            dq500_0bh.dsg_flash_info,
            dq500_0dl.dsg_flash_info,
            haldex4motion.haldex_flash_info,
            eps_mqb.eps_flash_info,
            gateway_mqb.gateway_flash_info,
        ][module_number]
        if self.flash_info == haldex4motion.haldex_flash_info:
            self.binfile_handler = haldex_binfile.HaldexBinFileHandler(self.flash_info)
        else:
            self.binfile_handler = binfile.BinFileHandler(self.flash_info)

    def report_error(self, context: str, exc: Exception):
        # Surface a worker/UDS failure in the feedback box instead of letting it
        # bubble up to the global excepthook, which calls wx.Exit() and kills the
        # whole GUI. A dead/timed-out connection shows up here as a udsoncan
        # "object of type 'NoneType' has no len()" TypeError (the transport
        # returned no frame), so give that case a human-readable hint.
        msg = "%s: %s: %s\n" % (context, type(exc).__name__, exc)
        self.feedback_text.AppendText(msg)
        text = str(exc).lower()
        if "nonetype" in text or "timeout" in text or "no len" in text:
            self.feedback_text.AppendText(
                "  -> No response from the ECU. Check that the ignition is on, "
                "that the interface is on a CAN bus that reaches this module "
                "(the gateway must route the diagnostic IDs), and that the "
                "diagnostic CAN IDs are correct.\n"
            )
        self.progress_bar.SetValue(0)
        logger.error(context, exc_info=exc)

    def on_get_info(self, event):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        try:
            ecu_info = flash_uds.read_ecu_data(
                self.flash_info,
                interface=interface,
                callback=self.update_callback,
                interface_path=interface_path,
            )
        except Exception as e:
            self.report_error("Get ECU info failed", e)
            return

        [
            self.feedback_text.AppendText(did + " : " + ecu_info[did] + "\n")
            for did in ecu_info
        ]

    def on_read_dtcs(self, event):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        try:
            dtcs = flash_uds.read_dtcs(
                self.flash_info,
                interface=interface,
                callback=self.update_callback,
                interface_path=interface_path,
            )
        except Exception as e:
            self.report_error("Read DTCs failed", e)
            return
        [
            self.feedback_text.AppendText(str(dtc) + " : " + dtcs[dtc] + "\n")
            for dtc in dtcs
        ]

    def on_dump_ccp(self, event):
        # Read the EPS per-car parametrization (flash 0x61000..0x63000) over the
        # proprietary raw-CAN CCP channel (lib/eps_ccp), non-destructively. This
        # is the way to read the LIVE dataset; the 0x35 RequestUpload "Dump ECU"
        # path is state-gated and returns 0x31 for intact blocks.
        if not module_selection_is_eps(self.module_choice.GetSelection()):
            self.feedback_text.AppendText(
                "Dump EPS (CCP) is only supported for the EPS MQB module.\n"
            )
            return

        (interface, interface_path) = split_interface_name(self.options["interface"])
        if interface != "BLEISOTP":
            self.feedback_text.AppendText(
                "EPS CCP requires the BLE dongle in raw-CAN mode "
                "(select a BLEISOTP interface).\n"
            )
            return

        # Region selection (like the "Dump ECU" block picker). The CCP read path
        # has no address whitelist, so any flash range is readable.
        # Each entry: (label, start, length, default filename).
        regions = [
            ("Parametrization 0x61000-0x63000 (8 KB)",
             0x61000, 0x2000, "EPS_MQB_parametrization_0x61000.bin"),
            ("Full ECU flash 0x0-0x85000 (~544 KB, slow)",
             0x0, 0x85000, "EPS_MQB_full.bin"),
            ("CAL + parametrization 0x58000-0x63000",
             0x58000, 0xB000, "EPS_MQB_cal_0x58000.bin"),
            ("H1 application 0x7000-0x58000",
             0x7000, 0x51000, "EPS_MQB_H1_0x7000.bin"),
            ("H7 bootloader 0x0-0x6000",
             0x0, 0x6000, "EPS_MQB_H7_0x0.bin"),
            ("H2 0x78000-0x85000",
             0x78000, 0xD000, "EPS_MQB_H2_0x78000.bin"),
        ]
        region_dlg = wx.SingleChoiceDialog(
            self,
            "Select the flash region to read over the CCP channel",
            "Dump EPS (CCP)",
            [r[0] for r in regions],
        )
        region_dlg.SetSelection(0)
        if region_dlg.ShowModal() != wx.ID_OK:
            region_dlg.Destroy()
            return
        _label, start, length, default_name = regions[region_dlg.GetSelection()]
        region_dlg.Destroy()

        save_dlg = wx.FileDialog(
            self,
            "Save EPS CCP dump as...",
            defaultFile=default_name,
            wildcard="*.bin",
            style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT,
        )
        if save_dlg.ShowModal() != wx.ID_OK:
            save_dlg.Destroy()
            return
        output_path = save_dlg.GetPath()
        save_dlg.Destroy()

        self.feedback_text.AppendText(
            "Starting EPS CCP dump of 0x%X-0x%X to %s\n"
            % (start, start + length, output_path)
        )
        self.progress_bar.SetValue(0)

        # The raw channel forwards every bus frame; suppress per-frame logging
        # for the duration regardless of the menu setting, then restore.
        frames_were_on = self.options.get("showframes", True)

        def progress(done, total):
            self.update_callback(
                flasher_step="EPS CCP dump",
                flasher_status="read 0x%X / 0x%X" % (done, total),
                flasher_progress=(done * 100.0 / total) if total else 0,
            )

        def dump_worker():
            try:
                if frames_were_on:
                    wx.CallAfter(self.apply_frame_logging, False)
                data = eps_ccp.dump_eps_parametrization(
                    interface,
                    start=start,
                    length=length,
                    interface_path=interface_path,
                    progress=progress,
                )
                Path(output_path).write_bytes(data)
                wx.CallAfter(
                    self.feedback_text.AppendText,
                    "EPS CCP dump complete: wrote %d bytes to %s\n"
                    % (len(data), output_path),
                )
                wx.CallAfter(self.progress_bar.SetValue, 0)
            except Exception as e:
                wx.CallAfter(self.report_error, "EPS CCP dump failed", e)
            finally:
                if frames_were_on:
                    wx.CallAfter(self.apply_frame_logging, True)

        dump_thread = threading.Thread(target=dump_worker)
        dump_thread.daemon = True
        dump_thread.start()

    def on_sniff_ccp(self, event):
        # First bring-up aid: enter raw mode, send CONNECT and print every
        # observed (id, data) frame for a few seconds so the operator can
        # confirm the channel answers and identify the DTO reply id. Frame
        # logging is intentionally left as-is (the volume here is tiny).
        if not module_selection_is_eps(self.module_choice.GetSelection()):
            self.feedback_text.AppendText(
                "Sniff EPS (CCP) is only supported for the EPS MQB module.\n"
            )
            return

        (interface, interface_path) = split_interface_name(self.options["interface"])
        if interface != "BLEISOTP":
            self.feedback_text.AppendText(
                "EPS CCP requires the BLE dongle in raw-CAN mode "
                "(select a BLEISOTP interface).\n"
            )
            return

        seconds = 5.0
        self.feedback_text.AppendText(
            "Sniffing EPS CCP for %.0fs (CRO 0x%X)...\n"
            % (seconds, eps_ccp.EPS_CRO_ID)
        )

        def sniff_worker():
            try:
                frames = eps_ccp.sniff_ccp(
                    interface, seconds=seconds, interface_path=interface_path
                )
                if not frames:
                    wx.CallAfter(
                        self.feedback_text.AppendText,
                        "No CAN frames observed. Check ignition, bus routing, "
                        "and that the dongle firmware supports raw mode.\n",
                    )
                    return
                counts = {}
                for arb_id, extended, frame_data in frames:
                    wx.CallAfter(
                        self.feedback_text.AppendText,
                        "RX 0x%08X %s %s\n"
                        % (
                            arb_id,
                            "EXT" if extended else "STD",
                            frame_data.hex(),
                        ),
                    )
                    counts[(arb_id, extended)] = counts.get((arb_id, extended), 0) + 1
                for (arb_id, extended), count in sorted(counts.items()):
                    wx.CallAfter(
                        self.feedback_text.AppendText,
                        "  id 0x%08X %s: %d frame(s)\n"
                        % (arb_id, "EXT" if extended else "STD", count),
                    )
            except Exception as e:
                wx.CallAfter(self.report_error, "EPS CCP sniff failed", e)

        sniff_thread = threading.Thread(target=sniff_worker)
        sniff_thread.daemon = True
        sniff_thread.start()

    def flash_unlock(self, selected_file):
        if (
            module_selection_is_dsg(self.module_choice.GetSelection())
            or module_selection_is_haldex(self.module_choice.GetSelection())
        ):
            self.feedback_text.AppendText(
                "SKIPPED: Unlocking is unnecessary for Haldex/DSG\n"
            )
            return

        input_bytes = Path(selected_file).read_bytes()
        if str.endswith(selected_file, ".frf"):
            self.feedback_text.AppendText("Extracting FRF for unlock...\n")
            (
                flash_data,
                allowed_boxcodes,
            ) = extract_flash.extract_flash_from_frf(
                input_bytes,
                self.flash_info,
                is_dsg=module_selection_is_dsg(self.module_choice.GetSelection()),
            )
            self.input_blocks = {}
            for i in self.flash_info.block_names_frf.keys():
                filename = self.flash_info.block_names_frf[i]
                self.input_blocks[filename] = constants.BlockData(
                    i, flash_data[filename]
                )

            cal_block = self.input_blocks[self.flash_info.block_names_frf[5]]
            file_box_code = str(
                cal_block.block_bytes[
                    self.flash_info.box_code_location[5][
                        0
                    ] : self.flash_info.box_code_location[5][1]
                ].decode()
            )
            if (
                file_box_code.strip()
                != self.flash_info.patch_info.patch_box_code.split("_")[0].strip()
            ):
                self.feedback_text.AppendText(
                    f"Boxcode mismatch for unlocking. Got box code {file_box_code} but expected {self.flash_info.patch_info.patch_box_code}. Please don't try to be clever. Supply the correct file and the process will work."
                )
                return

            self.input_blocks["UNLOCK_PATCH"] = constants.BlockData(
                self.flash_info.patch_info.patch_block_index + 5,
                Path(self.flash_info.patch_info.patch_filename).read_bytes(),
            )
            key_order = list(
                map(lambda i: self.flash_info.block_names_frf[i], [1, 2, 3, 4, 5])
            )
            key_order.insert(4, "UNLOCK_PATCH")
            input_blocks_with_patch = {k: self.input_blocks[k] for k in key_order}
            self.input_blocks = input_blocks_with_patch
            self.flash_bin(get_info=False)
        else:
            self.feedback_text.AppendText(
                "File did not appear to be a valid FRF. Unlocking is possible only with a specific FRF file for your ECU family.\n"
            )

    def flash_bin_file(self, selected_file, patch_cboot=False):
        input_bytes = Path(self.row_obj_dict[selected_file]).read_bytes()
        if str.endswith(self.row_obj_dict[selected_file], ".frf"):
            self.feedback_text.AppendText("Extracting FRF...\n")
            (
                flash_data,
                allowed_boxcodes,
            ) = extract_flash.extract_flash_from_frf(
                input_bytes,
                self.flash_info,
                is_dsg=module_selection_is_dsg(self.module_choice.GetSelection()),
            )
            self.input_blocks = {}
            for i in self.flash_info.block_names_frf.keys():
                filename = self.flash_info.block_names_frf[i]
                self.input_blocks[filename] = constants.BlockData(
                    i, flash_data[filename]
                )
            self.flash_bin(get_info=False, should_patch_cboot=patch_cboot)
        elif len(input_bytes) == self.flash_info.binfile_size:
            self.input_blocks = self.binfile_handler.blocks_from_bin(
                self.row_obj_dict[selected_file],
            )
            self.flash_bin(get_info=False, should_patch_cboot=patch_cboot)
        else:
            self.feedback_text.AppendText(
                "File did not appear to be a valid BIN or FRF\n"
            )

    def flash_flashpack(self, selected_file: str):
        # We're expecting a "FlashPack" ZIP
        with ZipFile(self.row_obj_dict[selected_file], "r") as zip_archive:
            if "file_list.json" not in zip_archive.namelist():
                self.feedback_text.AppendText(
                    "SKIPPING: No file listing found in archive\n"
                )

            else:
                with zip_archive.open("file_list.json") as file_list_json:
                    file_list = json.load(file_list_json)

                self.input_blocks = {}
                for filename in file_list:
                    self.input_blocks[filename] = simos_flash_utils.BlockData(
                        int(file_list[filename]), zip_archive.read(filename)
                    )

                self.flash_bin(get_info=False)

    def flash_cal(self, selected_file: str):
        # Flash a Calibration block only
        self.input_blocks = {}

        input_bytes = Path(self.row_obj_dict[selected_file]).read_bytes()
        if len(input_bytes) == self.flash_info.binfile_size:
            self.feedback_text.AppendText(
                "Extracting Calibration from full binary...\n"
            )
            has_driver = module_selection_is_dq250(self.module_choice.GetSelection()) or module_selection_is_dq400(self.module_choice.GetSelection())
            if has_driver:
                self.feedback_text.AppendText("Extracting Driver from full binary...\n")
            input_blocks = self.binfile_handler.blocks_from_bin(
                self.row_obj_dict[selected_file]
            )
            # Filter to only CAL block.
            self.input_blocks = {
                k: v
                for k, v in input_blocks.items()
                if (v.block_number == self.flash_info.block_name_to_number["CAL"])
                or (
                    has_driver
                    and v.block_number == self.flash_info.block_name_to_number["DRIVER"]
                )
            }
        else:
            if module_selection_is_dq250(self.module_choice.GetSelection()) or module_selection_is_dq400(self.module_choice.GetSelection()):
                # Populate DSG Driver block from a fixed file name if it's a CAL only bin
                dsg_driver_path = path.join(self.options["cal"], "FD_2.DRIVER.bin")
                self.feedback_text.AppendText(
                    "Loading DSG Driver from: " + dsg_driver_path + "\n"
                )
                self.input_blocks["FD_2.DRIVER.bin"] = constants.BlockData(
                    self.flash_info.block_name_to_number["DRIVER"],
                    Path(dsg_driver_path).read_bytes(),
                )
            self.input_blocks[self.row_obj_dict[selected_file]] = constants.BlockData(
                self.flash_info.block_name_to_number["CAL"],
                input_bytes,
            )

        self.flash_bin()

    def on_flash(self, event):
        if module_selection_is_gateway(self.module_choice.GetSelection()):
            self.feedback_text.AppendText(
                "Gateway module is Get-Info only; flashing is not supported here.\n"
            )
            return

        selected_file = self.list_ctrl.GetFirstSelected()
        if selected_file == -1:
            self.feedback_text.AppendText("SKIPPING: Select a file to flash!\n")
            return

        file_name = str(self.row_obj_dict[selected_file])

        module = self.module_choice.GetSelection()

        logger.critical("Selected: " + file_name)

        modal_response = wx.MessageDialog(
            None,
            "Are you sure you want to flash: "
            + file_name.rsplit("\\", 1)[-1]
            + "\n"
            + "To module: "
            + self.module_choice.GetString(module)
            + "?",
            "Confirm Flash",
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_WARNING | wx.CENTRE,
        ).ShowModal()

        if modal_response != wx.ID_YES:
            logger.info("User cancelled flash.")
            return

        choice = self.action_choice.GetSelection()
        if choice == 0:
            # "Flash Calibration"
            self.flash_cal(selected_file)

        elif choice == 1:
            # "Flash Flashpack"
            self.flash_flashpack(selected_file)

        elif choice == 2:
            # Flash BIN/FRF (unlocked)
            self.flash_bin_file(selected_file, patch_cboot=True)

        elif choice == 3:
            # Flash to stock
            self.flash_bin_file(selected_file, patch_cboot=False)

    def update_bin_listing(self, event=None):
        self.list_ctrl.ClearAll()

        self.list_ctrl.InsertColumn(0, "Filename", width=500)
        self.list_ctrl.InsertColumn(1, "Modify Time", width=140)

        if self.action_choice.GetSelection() == 0:
            # Calibration Flash
            bins = glob.glob(self.current_folder_path + "/*.bin")
            self.options["cal"] = self.current_folder_path
        elif self.action_choice.GetSelection() == 1:
            # Flashpack
            bins = glob.glob(self.current_folder_path + "/*.zip")
            self.options["flashpacks"] = self.current_folder_path
        elif self.action_choice.GetSelection() == 2:
            # Full BIN/FRF Unlocked
            bins = glob.glob(self.current_folder_path + "/*.bin")
            bins.extend(glob.glob(self.current_folder_path + "/*.frf"))
            self.options["bins"] = self.current_folder_path
        elif self.action_choice.GetSelection() == 3:
            # Unmodified flash
            bins = glob.glob(self.current_folder_path + "/*.bin")
            bins.extend(glob.glob(self.current_folder_path + "/*.frf"))
            self.options["bins"] = self.current_folder_path

        write_config(self.options)
        bins.sort(key=path.getmtime, reverse=True)

        bin_objects = []
        index = 0
        for bin_file in bins:
            self.list_ctrl.InsertItem(index, path.basename(bin_file))
            self.list_ctrl.SetItem(
                index,
                1,
                str(
                    datetime.fromtimestamp(path.getmtime(bin_file)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                ),
            )

            bin_objects.append(bin_file)
            self.row_obj_dict[index] = bin_file
            index += 1

    def threaded_callback(self, step, status, progress):
        self.GetParent().statusbar.SetStatusText(step)
        self.progress_bar.SetValue(round(float(progress)))
        self.feedback_text.AppendText(
            step + " - " + status + " - " + str(progress) + "\n"
        )

    def update_callback(self, **kwargs):
        if "flasher_step" in kwargs:
            wx.CallAfter(
                self.threaded_callback,
                kwargs["flasher_step"],
                kwargs["flasher_status"],
                kwargs["flasher_progress"],
            )
        else:
            wx.CallAfter(self.threaded_callback, kwargs["logger_status"], "0", 0)

    def prepare_file(self, selected_file, output_dir):
        should_patch_cboot = False

        if module_selection_is_dq250(self.module_choice.GetSelection()) or module_selection_is_dq400(self.module_choice.GetSelection()) or module_selection_is_dq500(self.module_choice.GetSelection()) or module_selection_is_dq500_0dl(self.module_choice.GetSelection()):
            flash_utils = dsg_flash_utils
        elif module_selection_is_dq381(self.module_choice.GetSelection()):
            flash_utils = dq381_flash_utils
        elif module_selection_is_haldex(self.module_choice.GetSelection()):
            flash_utils = haldex_flash_utils
        elif module_selection_is_eps(self.module_choice.GetSelection()):
            flash_utils = eps_flash_utils
        else:
            flash_utils = simos_flash_utils
            should_patch_cboot = True

        input_bytes = Path(selected_file).read_bytes()
        if len(input_bytes) != self.flash_info.binfile_size:
            self.feedback_text.AppendText(
                "File did not appear to be a valid BIN for "
                + self.module_choice.GetString(self.module_choice.GetSelection())
                + "\n"
            )
            return

        self.progress_bar.Pulse()

        self.feedback_text.AppendText(
            "Starting to prepare the following file : "
            + Path(selected_file).name
            + "\n"
        )

        input_blocks = self.binfile_handler.blocks_from_bin(selected_file)
        output_blocks = flash_utils.checksum_and_patch_blocks(
            self.flash_info, input_blocks, should_patch_cboot=should_patch_cboot
        )
        output_file = Path(output_dir, "PATCHED_" + Path(selected_file).name)
        outfile_data = self.binfile_handler.bin_from_blocks(output_blocks)
        output_file.write_bytes(outfile_data)

        self.feedback_text.AppendText(
            "File prepared and saved as : " + output_file.name + "\n"
        )

        self.progress_bar.SetValue(0)

    def flash_bin(self, get_info=True, should_patch_cboot=False):
        (interface, interface_path) = split_interface_name(self.options["interface"])
        if module_selection_is_dq250(self.module_choice.GetSelection()) or module_selection_is_dq400(self.module_choice.GetSelection()) or module_selection_is_dq500(self.module_choice.GetSelection()) or module_selection_is_dq500_0dl(self.module_choice.GetSelection()):
            flash_utils = dsg_flash_utils
        elif module_selection_is_dq381(self.module_choice.GetSelection()):
            flash_utils = dq381_flash_utils
        elif module_selection_is_haldex(self.module_choice.GetSelection()):
            flash_utils = haldex_flash_utils
        elif module_selection_is_eps(self.module_choice.GetSelection()):
            flash_utils = eps_flash_utils
        else:
            flash_utils = simos_flash_utils

        self.feedback_text.AppendText(
            "Starting to flash the following software components : \n"
            + self.binfile_handler.input_block_info(self.input_blocks)
            + "\n"
        )

        if get_info:
            ecu_info = flash_uds.read_ecu_data(
                self.flash_info,
                interface=interface,
                callback=self.update_callback,
                interface_path=interface_path,
            )

            [
                self.feedback_text.AppendText(did + " : " + ecu_info[did] + "\n")
                for did in ecu_info
            ]

        else:
            ecu_info = None

        for filename in self.input_blocks:
            fileBoxCode = str(
                self.input_blocks[filename]
                .block_bytes[
                    self.flash_info.box_code_location[
                        self.input_blocks[filename].block_number
                    ][0] : self.flash_info.box_code_location[
                        self.input_blocks[filename].block_number
                    ][
                        1
                    ]
                ]
                .decode()
            )

            if (
                ecu_info is not None
                and (
                    module_selection_is_dsg(self.module_choice.GetSelection())
                    or module_selection_is_haldex(self.module_choice.GetSelection())
                )
                is not True
                and ecu_info["VW Spare Part Number"].strip() != fileBoxCode.strip()
            ):
                self.feedback_text.AppendText(
                    "Attempting to flash a file that doesn't match box codes, exiting!: "
                    + ecu_info["VW Spare Part Number"]
                    + " != "
                    + fileBoxCode
                    + "\n"
                )
                return

        stmin_override = self.options.get("stmin_override", DEFAULT_STMIN)

        flasher_thread = threading.Thread(
            target=flash_utils.flash_bin,
            args=(
                self.flash_info,
                self.input_blocks,
                self.update_callback,
                interface,
                should_patch_cboot,
                interface_path,
                stmin_override,
            ),
        )
        flasher_thread.daemon = True
        flasher_thread.start()


class VW_Flash_Frame(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, parent=None, title="VW_Flash GUI", size=(640, 770))
        self.SetMinSize((480, 520))
        self.panel = FlashPanel(self)
        self.create_menu()
        self.statusbar = self.CreateStatusBar(1)
        self.statusbar.SetStatusText("Choose a bin file directory")
        self.hsl_logger = None
        self.selected_unlock = None
        self.Show()

    def create_menu(self):
        menu_bar = wx.MenuBar()

        file_menu = wx.Menu()
        open_folder_menu_item = file_menu.Append(
            wx.ID_ANY, "Open Folder...", "Open a folder with bins"
        )
        extract_frf_menu_item = file_menu.Append(
            wx.ID_ANY, "Extract FRF...", "Extract an FRF file"
        )
        menu_bar.Append(file_menu, "&File")
        self.Bind(
            event=wx.EVT_MENU, handler=self.on_open_folder, source=open_folder_menu_item
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_extract_frf,
            source=extract_frf_menu_item,
        )

        prepare_file_menu_item = file_menu.Append(
            wx.ID_ANY,
            "Prepare File...",
            "Checksums and patches a file for flashing to the selected ECU with a different tool",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_prepare_file,
            source=prepare_file_menu_item,
        )

        unlock_ecu_menu_item = file_menu.Append(
            wx.ID_ANY,
            "Unlock ECU...",
            "Choose the FRF file for unlocking the selected ECU",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_unlock,
            source=unlock_ecu_menu_item,
        )

        interface_menu = wx.Menu()

        select_interface_menu_item = interface_menu.Append(
            wx.ID_ANY, "Select Interface...", "Select a CAN or PassThru Interface"
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_interface,
            source=select_interface_menu_item,
        )

        scan_ble_menu_item = interface_menu.AppendCheckItem(
            wx.ID_ANY, "Scan for BLE devices", "Enable/disable scanning for BLE devices"
        )

        scan_ble_menu_item.Check(self.panel.options.get("scanble", False))

        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_scanble,
            source=scan_ble_menu_item,
        )

        set_stmin_menu_item = interface_menu.Append(
            wx.ID_ANY,
            "Change STMIN_TX...",
            "Change the transmit framing delay for interface",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_stmin,
            source=set_stmin_menu_item,
        )

        set_eps_ids_menu_item = interface_menu.Append(
            wx.ID_ANY,
            "Set EPS CAN IDs...",
            "Change the diagnostic request/response CAN IDs for the EPS module",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_select_eps_ids,
            source=set_eps_ids_menu_item,
        )

        show_frames_menu_item = interface_menu.AppendCheckItem(
            wx.ID_ANY,
            "Show raw CAN frames",
            "Show raw ISO-TP/UDS frames (TX/RX) in the window",
        )
        show_frames_menu_item.Check(self.panel.options.get("showframes", True))
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.on_toggle_show_frames,
            source=show_frames_menu_item,
        )

        menu_bar.Append(interface_menu, "&Interface")

        logger_menu = wx.Menu()
        logger_path_menu_item = logger_menu.Append(
            wx.ID_ANY,
            "Select logging path...",
            "Select folder for logging configuration and data.",
        )
        self.Bind(
            event=wx.EVT_MENU,
            handler=self.select_logger_path,
            source=logger_path_menu_item,
        )
        logger_menu_item = logger_menu.Append(
            wx.ID_ANY, "Start Logger", "Start Simos High Speed Logger"
        )
        self.Bind(
            event=wx.EVT_MENU, handler=self.on_start_logger, source=logger_menu_item
        )
        logger_stop_menu_item = logger_menu.Append(
            wx.ID_ANY, "Stop Logger", "Stop Simos High Speed Logger"
        )
        self.Bind(
            event=wx.EVT_MENU, handler=self.on_stop_logger, source=logger_stop_menu_item
        )

        logging_modes = ["22", "3E", "HSL"]
        logging_modes_menu = wx.Menu()
        for mode in logging_modes:
            radio_item = logging_modes_menu.AppendRadioItem(
                wx.ID_ANY, mode, "Logging Mode: " + mode
            )
            radio_item.Check(self.panel.options.get("logmode", "22") == mode)

            self.Bind(
                wx.EVT_MENU,
                lambda evt, temp=mode: self.on_select_logging_mode(evt, temp),
                source=radio_item,
            )

        logger_menu.AppendSubMenu(
            logging_modes_menu, "&Logging Mode", "Select Logging Mode"
        )
        menu_bar.Append(logger_menu, "&Logger")

        self.SetMenuBar(menu_bar)

    def on_open_folder(self, event):
        title = "Choose a directory:"
        dlg = wx.DirDialog(self, title, style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            self.panel.current_folder_path = dlg.GetPath()
            self.panel.update_bin_listing()
        dlg.Destroy()

    def on_select_logging_mode(self, event, mode):
        self.panel.options["logmode"] = mode
        write_config(self.panel.options)

    def on_select_scanble(self, event):
        self.panel.options["scanble"] = event.IsChecked()
        write_config(self.panel.options)

    def on_select_unlock(self, event):
        module = self.panel.module_choice.GetSelection()
        if module not in [0, 1]:
            self.panel.feedback_text.AppendText(
                "This module does not require unlocking!\n"
            )
            return

        dlg = UnlockDialog(
            self, "Select unlock FRF for " + self.panel.module_choice.GetString(module)
        )
        res = dlg.ShowModal()
        if res > 0:
            if self.selected_unlock == "":
                self.panel.feedback_text.AppendText(
                    "No FRF selected, aborting unlock!\n"
                )
                return
            self.panel.flash_unlock(self.selected_unlock)
        dlg.Destroy()

    def on_select_prepare_file(self, event):
        title = "Choose a file to prepare:"
        dlg = wx.FileDialog(self, title, style=wx.FD_DEFAULT_STYLE, wildcard="*.bin")
        if dlg.ShowModal() == wx.ID_OK:
            file_path = dlg.GetPath()
            dlg.Destroy()
            title = "Choose an output directory:"
            dlg = wx.DirDialog(self, title)
            if dlg.ShowModal() == wx.ID_OK:
                output_dir = dlg.GetPath()
                self.panel.prepare_file(file_path, output_dir)

            dlg.Destroy()

    def on_select_stmin(self, event):
        title = "Change STMIN_TX:"
        stmin_override = self.panel.options.get("stmin_override", DEFAULT_STMIN)
        dlg = StminDialog(self, title, stmin_override)
        res = dlg.ShowModal()
        if res > 0:
            self.panel.options["stmin_override"] = res
            write_config(self.panel.options)
        dlg.Destroy()

    def on_toggle_show_frames(self, event):
        enabled = event.IsChecked()
        self.panel.options["showframes"] = enabled
        write_config(self.panel.options)
        self.panel.apply_frame_logging(enabled)

    def on_select_eps_ids(self, event):
        tx_hex = str(self.panel.options.get("eps_txid", "0x712"))
        rx_hex = str(self.panel.options.get("eps_rxid", "0x77C"))
        dlg = EpsIdsDialog(self, "Set EPS CAN IDs", tx_hex, rx_hex)
        if dlg.ShowModal() == wx.ID_OK and dlg.result is not None:
            self.panel.options["eps_txid"], self.panel.options["eps_rxid"] = dlg.result
            write_config(self.panel.options)
            self.panel.apply_eps_ids()
            self.panel.feedback_text.AppendText(
                "EPS CAN IDs set to tx %s / rx %s\n" % dlg.result
            )
        dlg.Destroy()

    def select_logger_path(self, event):
        title = "Choose a directory for logging:"
        dlg = wx.DirDialog(self, title, style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            self.panel.options["logger"] = dlg.GetPath()
            write_config(self.panel.options)
        dlg.Destroy()

    def on_start_logger(self, event):
        if self.hsl_logger is not None:
            return

        if self.panel.options["logger"] == "":
            return

        (interface, interface_path) = split_interface_name(
            self.panel.options["interface"]
        )
        self.hsl_logger = simos_hsl.hsl_logger(
            runServer=False,
            interactive=False,
            mode=self.panel.options["logmode"],
            level=self.panel.options["activitylevel"],
            path=self.panel.options["logger"] + "/",
            callbackFunction=self.panel.update_callback,
            interface=interface,
            singleCSV=self.panel.options["singlecsv"],
            interfacePath=interface_path,
            displayGauges=False,
        )

        logger_thread = threading.Thread(target=self.hsl_logger.startLogger)
        logger_thread.daemon = True
        logger_thread.start()

        return

    def on_stop_logger(self, event):

        if self.hsl_logger is not None:
            self.hsl_logger.stop()
            self.hsl_logger = None

    def ble_scan_callback(self, interfaces, progress_dialog):
        progress_dialog.Update(100)
        self.panel.interfaces += interfaces
        dialog_interfaces = []
        self.panel.interfaces = list(
            filter(lambda interface: interface[0] is not None, self.panel.interfaces)
        )
        for interface in self.panel.interfaces:
            dialog_interfaces.append(interface[0])
        dlg = wx.SingleChoiceDialog(
            self, "Select an Interface", "Select an interface", dialog_interfaces
        )
        if dlg.ShowModal() == wx.ID_OK:
            self.panel.options["interface"] = self.panel.interfaces[dlg.GetSelection()][
                1
            ]
            write_config(self.panel.options)
            logger.info("User selected: " + self.panel.options["interface"])
        dlg.Destroy()

    def on_select_interface(self, event):
        progress_dialog = wx.ProgressDialog(
            "Scanning for devices...",
            "Checking J2534 and serial...",
            maximum=100,
            parent=self,
            style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
        )
        progress_dialog.Show()
        self.panel.interfaces = poll_interfaces()
        progress_dialog.Update(50, "Scanning for BLE devices...")

        def scan_finished(interfaces):
            wx.CallAfter(self.ble_scan_callback, interfaces, progress_dialog)

        if self.panel.options.get("scanble", False):
            scan_for_ble_devices(scan_finished)
        else:
            scan_finished([])

    def try_extract_frf(self, frf_data: bytes):
        flash_infos = [
            simos18.s18_flash_info,
            simos1810.s1810_flash_info,
            dq250mqb.dsg_flash_info,
            dq381.dsg_flash_info,
            dq400mqb.dsg_flash_info,
            dq500_0bh.dsg_flash_info,
            dq500_0dl.dsg_flash_info,
            haldex4motion.haldex_flash_info,
            simos184.s1841_flash_info,
            simos16.s16_flash_info,
            simos12.s12_flash_info,
            simos122.s122_flash_info,
            simos10.s10_flash_info,
            simos8.s8_flash_info,
        ]
        dsg_flash_infos = {dq250mqb.dsg_flash_info, dq381.dsg_flash_info, dq400mqb.dsg_flash_info, dq500_0bh.dsg_flash_info, dq500_0dl.dsg_flash_info}
        for flash_info in flash_infos:
            try:
                (flash_data, allowed_boxcodes) = extract_flash.extract_flash_from_frf(
                    frf_data,
                    flash_info,
                    is_dsg=(flash_info in dsg_flash_infos),
                )
                output_blocks = {}
                for i in flash_info.block_names_frf.keys():
                    filename = flash_info.block_names_frf[i]
                    output_blocks[filename] = constants.BlockData(
                        i, flash_data[filename], flash_info.number_to_block_name[i]
                    )
                return [output_blocks, flash_info]
            except:
                pass

    def extract_frf_task(self, frf_path: str, output_path: str, callback):
        frf_name = str.removesuffix(frf_path, ".frf")
        [output_blocks, flash_info] = self.try_extract_frf(Path(frf_path).read_bytes())
        if flash_info == haldex4motion.haldex_flash_info:
            bin_handler = haldex_binfile.HaldexBinFileHandler(flash_info)
        else:
            bin_handler = binfile.BinFileHandler(flash_info)
        outfile_data = bin_handler.bin_from_blocks(output_blocks)
        callback(50)
        Path(output_path, Path(frf_name).name + ".bin").write_bytes(outfile_data)

        for filename in output_blocks:
            output_block: constants.BlockData = output_blocks[filename]
            binary_data = output_block.block_bytes
            output_filename = (
                filename.rstrip(".bin") + "." + output_block.block_name + ".bin"
            )
            Path(output_path, output_filename).write_bytes(binary_data)
        callback(100)

    def on_select_extract_frf(self, event):
        title = "Choose an FRF file:"
        dlg = wx.FileDialog(self, title, style=wx.FD_DEFAULT_STYLE, wildcard="*.frf")
        if dlg.ShowModal() == wx.ID_OK:
            frf_file = dlg.GetPath()
            dlg.Destroy()
            title = "Choose an output directory:"
            dlg = wx.DirDialog(self, title)
            if dlg.ShowModal() == wx.ID_OK:

                def callback(progress):
                    wx.CallAfter(progress_dialog.Update, progress)

                output_dir = dlg.GetPath()
                progress_dialog = wx.ProgressDialog(
                    "Extracting FRF",
                    "Decrypting and unpacking...",
                    maximum=100,
                    parent=self,
                    style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE,
                )
                frf_thread = threading.Thread(
                    target=self.extract_frf_task,
                    args=(frf_file, output_dir, callback),
                )
                frf_thread.start()
                progress_dialog.Pulse()
                progress_dialog.Show()


if __name__ == "__main__":
    app = wx.App(False)
    frame = VW_Flash_Frame()
    app.SetTopWindow(frame)
    app.frame = frame
    app.MainLoop()
