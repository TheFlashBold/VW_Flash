from lib.constants import ControlModuleIdentifier, FlashInfo
from lib.crypto import plaintext

# VW MQB central gateway J533 (diagnostic address 0x19), e.g. 5Q0907530* /
# 5QE907530* (Renesas V850). This module exists ONLY to read ECU info
# (UDS 0x22 after an extended session) from the GUI; flashing is NOT wired up
# here on purpose.
#
# Diagnostic (ISO-TP) CAN IDs, confirmed against the 5Q0907530 firmware:
#   tester -> GW  (txid) = 0x710
#   GW -> tester  (rxid) = 0x77A   (the gateway's own response ID, referenced
#                                   hundreds of times in its diag handler)
gateway_control_module_identifier = ControlModuleIdentifier(0x77A, 0x710)

# Get-info does not need any of the flash machinery, so everything below is a
# minimal/empty placeholder just to satisfy the FlashInfo constructor.
_empty = {}

gateway_flash_info = FlashInfo(
    base_addresses=_empty,
    block_lengths=_empty,
    sa2_script=bytes(),
    block_names_frf=_empty,
    block_identifiers=_empty,
    block_checksums=_empty,
    control_module_identifier=gateway_control_module_identifier,
    software_version_location=_empty,
    box_code_location=_empty,
    block_transfer_sizes=_empty,
    binfile_layout=_empty,
    binfile_size=0,
    project_name="GATEWAY_MQB",
    crypto=plaintext.PlaintextCrypto(),
    block_name_to_number={},
    patch_info=None,
    checksum_block_location=None,
)
