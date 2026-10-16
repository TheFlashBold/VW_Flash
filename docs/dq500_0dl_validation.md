# DQ500 0DL preparation: offline evidence and remaining validation

The CLI `--dq500_0dl` option and GUI DQ500 0DL selection must use
`dq381_flash_utils`, not `dsg_flash_utils`. The latter is the legacy DSG
preparation path and applies a different checksum layout and transfer format.
DQ500 0BH remains on its existing path.

The base commit 04e40e8 already overrides DFI to 0xAA for 0DL in the legacy
handler. That fixes the DFI selection, but does not change its trailing-checksum
layout, placeholder CAL UDS checksum, or block-2 RAM-driver treatment. This
change selects the existing Bosch implementation for those remaining differences.

An original 0DL300013G / 2620 FRF was inspected offline. Its three blocks match
the current Bosch DQ381 preparation layout:

| Block | Base | Uncompressed bytes | Header CRC32 | Whole-block CRC32 |
| --- | --- | --- | --- | --- |
| BOOT | 0x010200 | 130560 | ADCC4D12 | E91A68D9 |
| ASW | 0x030200 | 1113600 | 17F6EB77 | E19E7423 |
| CAL | 0x140200 | 261632 | 3D45F91E | 74A8B988 |

The internal CRC is big-endian at offset 0x44, over the inclusive address range
specified at offsets 0x38 and 0x3C. Download preparation uses compression and
encryption identifiers 0xA/0xA, exact-output LZSS padding, and a big-endian
CRC32 of the complete uncompressed block for the UDS checksum. ASW block 2 is
an application block, not the legacy DSG RAM driver.

## Validation performed

- Standard-library dispatch tests exercise the actual CLI dispatch statements
  and both GUI dispatch sites without importing the GUI or transport stack.
  Run `python -m unittest discover -s tests -p test_dq500_routing.py -v`.
- A private offline harness executed the checksum and preparation function
  bodies on the original blocks and an altered CAL. All original blocks passed
  header validation unchanged. The original and altered CAL preparation outputs
  decrypted and decoded to their exact input bytes, with DFI 0xAA and correct
  whole-block CRCs. The harness isolated imports, supplied AES via cryptography,
  and used the previously compiled upstream C compressor with memory I/O.
  It did not exercise the packaged PyCryptodome/subprocess integration.
- Separate codec validation reproduced the original compressed CAL byte for
  byte using upstream C code at 293f46d782bae2ced930497889b71eb782f122cb.

No firmware binaries, vehicle identifiers, or private diagnostic logs are
included. The offline fixture is one software version, not evidence for every
DQ500 variant.

## Hardware validation still required

This routing correction does not establish successful ECU programming. It also
changes which existing `flash_bin` implementation is selected, including the
Bosch path's `dq3xx_hack=True`; that transport behavior remains unvalidated here.
This PR does not change erase retries, download parameters, or recovery logic.

Before treating support as proven, reviewers need a supported recovery method
and backup, then hardware logs covering erase, RequestDownload, transfer,
checksum validation, reset, and return to stock on compatible test hardware.
Importing a file or passing offline CRC checks alone does not establish recovery.

Related discussion: https://github.com/bri3d/VW_Flash/issues/161
