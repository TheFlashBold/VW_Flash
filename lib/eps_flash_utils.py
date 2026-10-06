import logging
import zlib
from typing import Optional

from . import constants
from . import flash_uds
from .constants import BlockData, FlashInfo, PreparedBlockData

cliLogger = logging.getLogger("SimosFlashHistory")

# MQB EPS (ZF, 3Q0/5Q0909144*, V850). Flashing reuses the generic UDS flow
# (flash_uds.flash_blocks): all services it needs exist in the EPS bootloader
# (0x10/0x11/0x27/0x2E/0x31 with routines 0x0203/0x0202/0xFF00/0xFF01, 0x34/0x36/0x37).
#
# Block integrity is a keyless CRC-32 (zlib) over the whole block, transmitted in
# the checkMemory routine (0x31 0x01 0x0202). flash_uds.flash_block already sends
# `[0x01, block_id, 0x00, 0x04] + uds_checksum`, which the EPS bootloader parser
# (checkMemory @ ECU 0x39ac) reads as: ALFID 0x01 (addr length 1 = block index),
# block index, checksum length 0x0004, then the 4-byte expected CRC. So we only
# need uds_checksum = CRC-32 big-endian; the bootloader computes the CRC over the
# flashed block and compares. No compression, no encryption (DFI 0x00).
#
# NOTE: not yet verified against a real ECU. Always keep a RequestUpload dump
# (VW_Flash.py --eps --action dump) as a restore image before flashing.


def prepare_blocks(
    flash_info: FlashInfo, input_blocks: dict[str, BlockData], callback=None
) -> dict[str, PreparedBlockData]:
    output_blocks = {}
    for filename in input_blocks:
        block: BlockData = input_blocks[filename]
        binary_data = block.block_bytes
        blocknum = block.block_number
        blockname = flash_info.number_to_block_name[blocknum]

        try:
            start, end = flash_info.box_code_location[blocknum]
            boxcode = binary_data[start:end].decode() if end > start else "-"
        except Exception:
            boxcode = "-"

        # Expected CRC the bootloader checkMemory routine compares against.
        uds_checksum = zlib.crc32(binary_data).to_bytes(4, "big")

        output_blocks[filename] = PreparedBlockData(
            blocknum,
            binary_data,
            boxcode,
            0x0,  # encryption: none
            0x0,  # compression: none
            True,  # erase before download
            uds_checksum,
            blockname,
        )
    return output_blocks


def flash_bin(
    flash_info: FlashInfo,
    input_blocks: dict[str, BlockData],
    callback=None,
    interface: str = "CAN",
    patch_cboot=False,  # EPS has no CBOOT RSA patch; accepted for a uniform signature
    interface_path: Optional[str] = None,
    stmin_override: Optional[int] = None,
):
    prepared_blocks = prepare_blocks(flash_info, input_blocks, callback)

    # The uploaded/edited block length is authoritative (should equal the whole
    # block; the bootloader requires the full block).
    for filename in prepared_blocks:
        block = prepared_blocks[filename]
        flash_info.block_lengths[block.block_number] = len(block.block_encrypted_bytes)

    flash_uds.flash_blocks(
        flash_info=flash_info,
        block_files=prepared_blocks,
        callback=callback,
        interface=interface,
        interface_path=interface_path,
        stmin_override=stmin_override,
    )
