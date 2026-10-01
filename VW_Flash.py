from pathlib import Path
import asyncio
import tqdm
import logging
import logging.config
import argparse
import sys
from os import path

from lib import haldex_binfile
from lib.extract_flash import extract_flash_from_frf, ExternContainer
from lib.constants import (
    BlockData,
    PreparedBlockData,
    FlashInfo,
)
import lib.binfile as binfile
import lib.simos_flash_utils as simos_flash_utils
import lib.dq381_flash_utils as dq381_flash_utils
import lib.dsg_flash_utils as dsg_flash_utils
import lib.haldex_flash_utils as haldex_flash_utils

import lib.flash_uds as flash_uds

from lib.modules import (
    simos8,
    simos10,
    simos12,
    simos122,
    simos18,
    simos1810,
    simos184,
    dq200mqb,
    dq250mqb,
    dq381,
    dl382,
    dq400mqb,
    dq500_0bh,
    dq500_0dl,
    dl501,
    vl381,
    simos16,
    haldex4motion,
    al450,
    al551,
    al991,
    edc17c64,
)
from lib.containers import bosch, dsg_premqb_sgo, vl300_sgo, pcr21, gateway

from lib.simos_hsl import hsl_logger
import shutil

# Get an instance of logger, which we'll pull from the config file
logger = logging.getLogger("VWFlash")

try:
    currentPath = path.dirname(path.abspath(__file__))
except NameError:  # We are the main py2exe script, not a module
    currentPath = path.dirname(path.abspath(sys.argv[0]))

logging.config.fileConfig(path.join(currentPath, "logging.conf"))

logger.info("Starting VW_Flash.py")

if sys.platform == "win32":
    defaultInterface = "J2534"
else:
    defaultInterface = "SocketCAN_can0"

logger.debug("Default interface set to " + defaultInterface)

# Default to Simos18 Flash Info for building help

flash_info = simos18.s18_flash_info

# build a List of valid block parameters for the help message
block_number_help = []
for name, number in flash_info.block_name_to_number.items():
    block_number_help.append(name)
    block_number_help.append(str(number))

# Set up the argument/parser with run options
parser = argparse.ArgumentParser(
    description="VW_Flash CLI",
    epilog="The MAIN CLI interface for using the tools herein",
)
parser.add_argument(
    "--action",
    help="The action you want to take",
    choices=[
        "checksum",
        "checksum_ecm3",
        "lzss",
        "encrypt",
        "prepare",
        "flash_cal",
        "flash_bin",
        "flash_frf",
        "flash_unlock",
        "extract_frf",
        "get_ecu_info",
        "get_dtcs",
        "log",
    ],
    required=True,
)
parser.add_argument(
    "--infile", help="the absolute path of an inputfile", action="append"
)

parser.add_argument(
    "--block",
    type=str,
    help="The block name or number",
    choices=block_number_help,
    action="append",
    required=False,
)

parser.add_argument(
    "--frf",
    type=str,
    help="An (optional) FRF file to source flash data from",
    required=False,
)

parser.add_argument("--dsg", help="Perform MQB-DQ250 DSG actions.", action="store_true")
parser.add_argument("--dq200", help="Perform MQB-DQ200 DSG actions.", action="store_true")
parser.add_argument("--dq381", help="Perform DQ381 flash actions.", action="store_true")
parser.add_argument("--dl382", help="Perform DL382 (0CK Conti/SH-2A) flash actions.", action="store_true")
parser.add_argument("--dq400", help="Perform DQ400 DSG actions.", action="store_true")
parser.add_argument("--dq500", help="Perform DQ500-0BH DSG actions.", action="store_true")
parser.add_argument("--dq500_0dl", help="Perform DQ500-0DL DSG actions.", action="store_true")
parser.add_argument("--dl501", help="DL501 0B5 S tronic, extract_frf only.", action="store_true")
parser.add_argument("--vl381", help="VL381 0AW multitronic, extract_frf only.", action="store_true")
parser.add_argument("--al450", help="ZF 8HP AL450 (2H0927158*, Amarok), extract_frf only.", action="store_true")
parser.add_argument("--al551", help="ZF 8HP AL551 (4G0927158*/4H1927158*), extract_frf only.", action="store_true")
parser.add_argument("--al991", help="ZF 8HP AL991 (0C8927750*), extract_frf only.", action="store_true")
parser.add_argument("--edc17c64", help="Bosch EDC17C64 (04L906021*), extract_frf only.", action="store_true")
# Self-addressed containers (SGO / BCB / Aisin ODX ...): the layout comes from the
# container itself (lib/containers), not from a FlashInfo. extract_frf only.
parser.add_argument("--edc17", help="Bosch BCB Type1 / LZSS10 FRF, ODX or SGO (EDC17, MED17, MED9), extract_frf only.", action="store_true")
parser.add_argument("--aisin", help="Aisin 09G/09D/09S FRF, ODX or SGO, extract_frf only.", action="store_true")
parser.add_argument("--sgo_raw", help="Plain XOR-0xFF SGO (Marelli AMT, Siemens transfer case), extract_frf only.", action="store_true")
parser.add_argument("--dq250_premqb", help="Pre-MQB DQ250 02E SGO, extract_frf only.", action="store_true")
parser.add_argument("--vl300", help="VL300 01J multitronic SGO, extract_frf only.", action="store_true")
parser.add_argument("--pcr21", help="Simos PCR2.1 (03L906023*) FRF, extract_frf only.", action="store_true")
parser.add_argument("--gateway", help="Gateway J533 (5Q0/5QE/5WA/8P0907530*) FRF or SGO, extract_frf only.", action="store_true")
parser.add_argument(
    "--unsafe_haldex",
    help="Perform Haldex actions, unsafe to flash modified files!",
    action="store_true",
    dest="haldex",
)

parser.add_argument(
    "--patch-cboot",
    help="Automatically patch CBOOT into Sample Mode",
    action="store_true",
)

parser.add_argument("--simos8", help="specify simos8", action="store_true")
parser.add_argument("--simos10", help="specify simos10", action="store_true")
parser.add_argument("--simos12", help="specify simos12", action="store_true")
parser.add_argument("--simos122", help="specify simos12.2", action="store_true")
parser.add_argument("--simos16", help="specify simos16", action="store_true")
parser.add_argument("--simos1810", help="specify simos18.10", action="store_true")
parser.add_argument("--simos1841", help="specify simos18.41", action="store_true")


parser.add_argument(
    "--is_early", help="specify an early car for ECM3 checksumming", action="store_true"
)

parser.add_argument(
    "--input_bin",
    type=str,
    help="An (optional) single BIN file to attempt to parse into flash data",
    required=False,
)

parser.add_argument(
    "--output_bin",
    help="output a single BIN file, as used by some commercial tools",
    type=str,
    required=False,
)

parser.add_argument(
    "--template",
    type=str,
    help="extract_frf: full flash read whose bootloader/gap bytes are kept in the output bin "
    "(default: 0x00-filled)",
    required=False,
)

parser.add_argument(
    "--interface",
    help="specify an interface type",
    choices=["J2534", "SocketCAN", "BLEISOTP", "USBISOTP", "TEST"],
    default=defaultInterface,
)

parser.add_argument(
    "--ble_name", help="Pass a custom device name for the BLEISOTP adapter"
)

parser.add_argument(
    "--usb_name",
    help="Pass a serial port identifier for the USB ISOTP A0 Firmware. Find one using python -m serial.tools.list_ports",
)

parser.add_argument(
    "--mode",
    type=str,
    help="Logging mode",
    choices=["22", "3E", "HSL"],
    default="22",
    required=False,
)

args = parser.parse_args()

if args.simos8:
    flash_info = simos8.s8_flash_info

if args.simos10:
    flash_info = simos10.s10_flash_info

if args.simos12:
    flash_info = simos12.s12_flash_info

if args.simos122:
    flash_info = simos122.s122_flash_info

if args.simos1810:
    flash_info = simos1810.s1810_flash_info

if args.simos1841:
    flash_info = simos184.s1841_flash_info

if args.simos16:
    flash_info = simos16.s16_flash_info

if args.dsg:
    flash_info = dq250mqb.dsg_flash_info

if args.dq200:
    flash_info = dq200mqb.dsg_flash_info

if args.haldex:
    flash_info = haldex4motion.haldex_flash_info

if args.dq381:
    flash_info = dq381.dsg_flash_info

if args.dl382:
    flash_info = dl382.dsg_flash_info

if args.dq400:
    flash_info = dq400mqb.dsg_flash_info

if args.dq500:
    flash_info = dq500_0bh.dsg_flash_info

if args.dq500_0dl:
    flash_info = dq500_0dl.dsg_flash_info

if args.dl501:
    flash_info = dl501.dsg_flash_info

if args.vl381:
    flash_info = vl381.dsg_flash_info

# DL501/VL381 and the ZF 8HP TCUs: FRF container/codec and flat layout are
# known, flashing is not (no SA2 script, block checksums or transfer
# parameters) -> extract only.
if args.edc17c64:
    flash_info = edc17c64.edc17c64_flash_info

container = None
container_name = None
for flag, extractor in (
    ("edc17", lambda p, d: bosch.extract_container(p, d, bosch.CODECS_BOSCH)),
    ("aisin", lambda p, d: bosch.extract_container(p, d, bosch.CODECS_AISIN)),
    ("sgo_raw", lambda p, d: bosch.extract_container(p, d, bosch.CODECS_SGO_RAW)),
    ("dq250_premqb", dsg_premqb_sgo.extract_container),
    ("vl300", vl300_sgo.extract_container),
    ("pcr21", pcr21.extract_container),
    ("gateway", gateway.extract_container),
):
    if getattr(args, flag):
        container, container_name = extractor, flag

extract_only = (
    args.dl501 or args.vl381 or args.al450 or args.al551 or args.al991
    or args.edc17c64 or container is not None
)
is_dsg = (
    args.dsg or args.dq200 or args.dq381 or args.dl382 or args.dq400
    or args.dq500 or args.dq500_0dl or extract_only
)

if args.al450:
    flash_info = al450.dsg_flash_info

if args.al551:
    flash_info = al551.dsg_flash_info

if args.al991:
    flash_info = al991.dsg_flash_info

# Modules that know their checksums on the full flat image (FlashInfo
# checksum_image / checksum_fix_image, e.g. AL551/AL450) can also check
# (checksum) and correct (prepare --output_bin) a bin without flash support.
image_checksum = container is None and hasattr(flash_info, "checksum_image")
allowed_actions = ("extract_frf", "checksum", "prepare") if image_checksum else ("extract_frf",)
if extract_only and args.action not in allowed_actions:
    logger.critical(
        f"{container_name or flash_info.project_name} only supports --action "
        + " / ".join(allowed_actions)
    )
    exit(1)


def log_image_checksums(image: bytes) -> bool:
    results = flash_info.checksum_image(image)
    for name, location, stored, calculated in results:
        state = "OK" if stored == calculated else "INVALID"
        logger.info(
            f"{name}: checksum @{location:#x} stored {stored:#010x} calculated {calculated:#010x} {state}"
        )
    if not results:
        logger.warning(f"no {flash_info.project_name} checksum block found")
    return bool(results) and all(stored == calculated for _, _, stored, calculated in results)


if extract_only and image_checksum and args.action in ("checksum", "prepare"):
    if not args.input_bin:
        logger.critical(f"--action {args.action} for {flash_info.project_name} needs --input_bin (full image)")
        exit(1)
    image = Path(args.input_bin).read_bytes()
    if args.action == "checksum":
        exit(0 if log_image_checksums(image) else 1)
    if not args.output_bin:
        logger.critical("--action prepare needs --output_bin")
        exit(1)
    image = flash_info.checksum_fix_image(image)
    log_image_checksums(image)
    Path(args.output_bin).write_bytes(image)
    logger.info(f"Wrote {args.output_bin}")
    exit(0)

flash_utils = simos_flash_utils

if args.dsg or args.dq200 or args.dq400 or args.dq500 or args.dq500_0dl:
    flash_utils = dsg_flash_utils

if args.dq381 or args.dl382:
    flash_utils = dq381_flash_utils

if args.haldex:
    flash_utils = haldex_flash_utils
    binfile_handler = haldex_binfile.HaldexBinFileHandler(flash_info)
else:
    binfile_handler = binfile.BinFileHandler(flash_info)

if args.interface == "BLEISOTP":
    from bleak import BleakScanner
    from lib.constants import BLE_SERVICE_IDENTIFIER

    ble_device_name = "BLE_TO_ISOTP20"
    if args.ble_name:
        ble_device_name = args.ble_name

    async def scan_for_devices(name):
        devices = await BleakScanner.discover(service_uuids=[BLE_SERVICE_IDENTIFIER])
        for d in devices:
            if d.name == name:
                return d
        raise RuntimeError("Did not find a BLE_ISOTP device named " + name)

    logger.info("Searching for BLE device named " + ble_device_name)
    device = asyncio.run(scan_for_devices(ble_device_name))
    args.interface = "BLEISOTP_" + device.address
    logger.info("Found BLE device with address: " + args.interface)

if args.interface == "USBISOTP":
    if args.usb_name is None:
        logger.error(
            "Cannot use USB-ISOTP without specifying a serial device using --usb_name . List serial devices using python -m serial.tools.list_ports"
        )
        exit()
    args.interface = "USBISOTP_" + args.usb_name


def input_blocks_from_frf(frf_path: str) -> dict[str, BlockData]:
    frf_data = Path(frf_path).read_bytes()
    try:
        (flash_data, allowed_boxcodes) = extract_flash_from_frf(
            frf_data, flash_info, is_dsg=is_dsg
        )
    except ExternContainer:
        logger.critical(
            "FRF uses the ODX-F container (newer gen); its decryption key is not available"
        )
        exit(1)
    input_blocks = {}
    for i in flash_info.block_names_frf.keys():
        filename = flash_info.block_names_frf[i]
        input_blocks[filename] = BlockData(i, flash_data[filename])
    return input_blocks


if args.action == "flash_cal":
    args.block = ["CAL"]

# if the number of block args doesn't match the number of file args, log it and exit
if (args.infile and not args.block) or (
    args.infile and (len(args.block) != len(args.infile))
):
    logger.critical("You must specify a block for every infile")
    exit()

# convert --blocks on the command line into a list of ints
if args.block:
    blocks = [int(flash_info.block_to_number(block)) for block in args.block]

if args.frf and container is None:
    input_blocks = input_blocks_from_frf(args.frf)

if args.input_bin:
    input_blocks = binfile_handler.blocks_from_bin(args.input_bin)
    logger.info(binfile_handler.input_block_info(input_blocks))

# build the dict that's used to proces the blocks
#  'filename' : BlockData (block_number, binary_data)
if args.infile and args.block:
    input_blocks: dict[str, BlockData] = {}
    for i in range(0, len(args.infile)):
        input_blocks[args.infile[i]] = BlockData(
            blocks[i], Path(args.infile[i]).read_bytes()
        )


def callback_function(t, flasher_step, flasher_status, flasher_progress):
    t.update(round(flasher_progress - t.n))
    t.set_description(flasher_status, refresh=True)


def flash_bin(flash_info: FlashInfo, input_blocks: dict[str, BlockData]):
    logger.info(binfile_handler.input_block_info(input_blocks))

    t = tqdm.tqdm(
        total=100,
        colour="green",
        ncols=round(shutil.get_terminal_size().columns * 0.75),
    )

    def wrap_callback_function(flasher_step, flasher_status, flasher_progress):
        callback_function(t, flasher_step, flasher_status, float(flasher_progress))

    flash_utils.flash_bin(
        flash_info,
        input_blocks,
        wrap_callback_function,
        interface=args.interface,
        patch_cboot=args.patch_cboot,
    )

    t.close()


# if statements for the various cli actions
if args.action == "checksum":
    flash_utils.checksum(flash_info=flash_info, input_blocks=input_blocks)

elif args.action == "checksum_ecm3":
    simos_flash_utils.checksum_ecm3(
        flash_info, input_blocks, is_early=(args.is_early or args.simos12)
    )

elif args.action == "lzss":
    simos_flash_utils.lzss_compress(input_blocks, args.outfile)

elif args.action == "encrypt":
    output_blocks = flash_utils.encrypt_blocks(flash_info, input_blocks)

    for filename in output_blocks:
        output_block: PreparedBlockData = output_blocks[filename]
        binary_data = output_block.block_encrypted_bytes
        blocknum = output_block.block_number

        outfile = filename + ".flashable_block" + str(blocknum)
        logger.info("Writing encrypted file to: " + outfile)
        Path(outfile).write_bytes(binary_data)

elif args.action == "prepare":
    output_blocks = flash_utils.checksum_and_patch_blocks(
        flash_info, input_blocks, should_patch_cboot=args.patch_cboot
    )

    if args.output_bin:
        outfile_data = binfile_handler.bin_from_blocks(output_blocks)
        Path(args.output_bin).write_bytes(outfile_data)
    else:
        for filename in output_blocks:
            output_block: BlockData = output_blocks[filename]
            binary_data = output_block.block_bytes
            block_number = output_block.block_number
            file_name = filename.rstrip(".bin") + "." + output_block.block_name + ".bin"
            Path(file_name).write_bytes(binary_data)

elif args.action == "extract_frf":
    if not args.frf or not args.output_bin:
        logger.critical("extract_frf needs --frf and --output_bin")
        exit(1)
    output_bin = Path(args.output_bin)
    out_dir = output_bin if output_bin.is_dir() else None
    if container is not None:
        # the container carries its own layout; it also proposes the file name
        try:
            image, name = container(Path(args.frf), out_dir)
        except Exception as e:
            logger.critical(f"{Path(args.frf).name}: {e}")
            exit(1)
        if out_dir:
            output_bin = out_dir / name
        output_bin.write_bytes(image)
        logger.info(f"Wrote {output_bin}")
        exit(0)
    if out_dir:
        # FL_<boxcode>_<version>_<...>.frf -> <boxcode>_<version>.bin; separators
        # may be '-' and dash-padded (FL-8K5927156B--0004.frf).
        import re
        m = re.match(r"^FL[-_]+([0-9A-Za-z]+)[-_]+([0-9A-Za-z]+)(?:[-_].*)?\.frf$",
                     Path(args.frf).name, re.I)
        stem = f"{m.group(1)}_{m.group(2)}" if m else Path(args.frf).stem
        if hasattr(flash_info, "output_name"):
            name = flash_info.output_name(stem, [b.block_bytes for b in input_blocks.values()])
        else:
            name = f"{stem}.bin"
        output_bin = out_dir / name
    base = None
    if args.template:
        base = Path(args.template).read_bytes()
        if len(base) != flash_info.binfile_size:
            logger.critical(
                f"template is {len(base):#x} bytes, expected {flash_info.binfile_size:#x}"
            )
            exit(1)
    logger.info(binfile_handler.input_block_info(input_blocks))
    image = binfile_handler.bin_from_blocks(input_blocks, base)
    output_bin.write_bytes(image)
    logger.info(f"Wrote {output_bin}")
    if image_checksum and not log_image_checksums(image):
        logger.warning("checksum mismatch in the extracted image")

elif args.action == "flash_cal":
    t = tqdm.tqdm(
        total=100,
        colour="green",
        ncols=round(shutil.get_terminal_size().columns * 0.75),
    )

    def wrap_callback_function(flasher_step, flasher_status, flasher_progress):
        callback_function(t, flasher_step, flasher_status, float(flasher_progress))

    ecuInfo = flash_uds.read_ecu_data(
        flash_info, interface=args.interface, callback=wrap_callback_function
    )

    for did in ecuInfo:
        logger.debug(did + " - " + ecuInfo[did])

    logger.info(binfile_handler.input_block_info(input_blocks))

    cal_flash_blocks = {}

    for filename in input_blocks:
        input_block = input_blocks[filename]
        if input_block.block_number != flash_info.block_name_to_number["CAL"]:
            continue
        file_box_code = str(
            input_block.block_bytes[
                flash_info.box_code_location[input_block.block_number][
                    0
                ] : flash_info.box_code_location[input_block.block_number][1]
            ].decode()
        )

        if ecuInfo["VW Spare Part Number"].strip() != file_box_code.strip():
            logger.critical(
                "Attempting to flash a file that doesn't match box codes, exiting!: "
                + ecuInfo["VW Spare Part Number"]
                + " != "
                + file_box_code
            )
            exit()
        else:
            logger.critical("File matches ECU box code")
        cal_flash_blocks[filename] = input_block

    flash_utils.flash_bin(
        flash_info, cal_flash_blocks, wrap_callback_function, interface=args.interface
    )

    t.close()

elif args.action == "flash_frf":
    flash_bin(flash_info, input_blocks)

elif args.action == "flash_unlock":
    cal_block = input_blocks[flash_info.block_names_frf[5]]
    file_box_code = str(
        cal_block.block_bytes[
            flash_info.box_code_location[5][0] : flash_info.box_code_location[5][1]
        ].decode()
    )
    if (
        file_box_code.strip()
        != flash_info.patch_info.patch_box_code.split("_")[0].strip()
    ):
        logger.error(
            f"Boxcode mismatch for unlocking. Got box code {file_box_code} but expected {flash_info.patch_info.patch_box_code}"
        )
        exit()

    input_blocks["UNLOCK_PATCH"] = BlockData(
        flash_info.patch_info.patch_block_index + 5,
        Path(flash_info.patch_info.patch_filename).read_bytes(),
    )

    key_order = list(map(lambda i: flash_info.block_names_frf[i], [1, 2, 3, 4, 5]))
    key_order.insert(4, "UNLOCK_PATCH")
    input_blocks_with_patch = {k: input_blocks[k] for k in key_order}

    flash_bin(flash_info, input_blocks_with_patch)

elif args.action == "flash_bin":
    flash_bin(flash_info, input_blocks)

elif args.action == "get_ecu_info":
    t = tqdm.tqdm(
        total=100,
        colour="green",
        ncols=round(shutil.get_terminal_size().columns * 0.75),
    )

    def wrap_callback_function(flasher_step, flasher_status, flasher_progress):
        callback_function(t, flasher_step, flasher_status, float(flasher_progress))

    ecu_info = flash_uds.read_ecu_data(
        flash_info, interface=args.interface, callback=wrap_callback_function
    )

    [t.write(did + " : " + ecu_info[did]) for did in ecu_info]

    t.close()

elif args.action == "get_dtcs":
    t = tqdm.tqdm(
        total=100,
        colour="green",
        ncols=round(shutil.get_terminal_size().columns * 0.75),
    )

    def wrap_callback_function(flasher_step, flasher_status, flasher_progress):
        callback_function(t, flasher_step, flasher_status, float(flasher_progress))

    dtcs = flash_uds.read_dtcs(
        flash_info, interface=args.interface, callback=wrap_callback_function
    )
    [t.write(str(dtc) + " : " + dtcs[dtc]) for dtc in dtcs]

    t.close()

elif args.action == "log":
    logger = hsl_logger(
        runServer=False,
        interactive=True,
        mode=args.mode,
        level="INFO",
        path="./logs/",
        callbackFunction=None,
        interface=args.interface,
        singleCSV=False,
        interfacePath=None,
        displayGauges=True,
    )

    logger.startLogger()
