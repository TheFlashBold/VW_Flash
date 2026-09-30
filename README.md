# VW_Flash

VW Flashing Tools over ISO-TP / UDS

Currently supports full custom reflashing of the Continental/Siemens Simos18.1/6, and Simos18.10 control units as used in MQB VW AG vehicles, as well as the Temic DQ250-MQB, Bosch DQ381-MQB DSG, DQ400-MQB DSG, DQ500-0BH DSG, DQ500-0DL DSG, Continental DL382 (0CK) DSG, and Gen 5 Haldex4Motion control units over UDS.

RSA-bypass/"unlock" patches are provided for Simos 18.1/6 (SC8 project identifier) and Simos18.10 (SCG project identifier). 

Additionally supports reflashing of several other Simos ECUs provided that RSA validation (if present) has already been disabled.

# Changes to original VW_Flash

- **Additional DSG transmissions**: Full flash support for DQ381-MQB, DQ400-MQB, DQ500-0BH, DQ500-0DL, DL382 (0CK), DL501 (0B5) and VL381 (0AW), alongside the original DQ250-MQB.
- **DL382 (0CK)**: Added the Continental/Temic DL382 mechatronic (`--dl382`) — unencrypted, LZSS10-compressed flash blocks with SA2 seed/key and per-block CRC-32.
- **ZF 8HP / Haldex**: Added AL551 and AL991 (ZF 8HP) and Gen 5 Haldex4Motion support.
- **Additional engine ECUs**: Added Bosch EDC17, EDC17C64, MED17.5 and MED17.5.2 modules.
- **macOS build**: Signed and notarized VW_Flash_GUI app bundle for Apple Silicon.
- **extractodx.py**: Fixed decompression for unencrypted DSG containers (compressionType='0' check before LZSS10 fallback).

# Use Information and Documentation

Prebuilt releases for Windows are available at : https://github.com/bri3d/VW_Flash/releases

[docs/windows.md](docs/windows.md) contains detailed setup instructions to use a point and click interface called VW_Flash_GUI to create a "virtual read" and unlock Simos18 for writing unsigned code and calibration.

[docs/cli.md](docs/cli.md) contains documentation about the command line interface VW_Flash. 

## macOS Build

A prebuilt macOS app bundle is available from the GitHub release:

[Download VW_Flash_GUI for macOS (Apple Silicon)](https://github.com/TheFlashBold/VW_Flash/releases/download/v0.7.3-macos.4/VW_Flash_GUI-macos-arm64.zip)

The macOS app is signed and notarized with Apple Developer ID, includes the required Bluetooth permission description, and is packaged without resource forks or AppleDouble metadata.

Unzip the archive and open `VW_Flash_GUI.app`. The app stores its GUI configuration and logs in `~/Library/Application Support/VW_Flash`.

# Supported Interface Hardware

* Macchina A0 with BridgeLEG firmware, via J2534: https://github.com/Switchleg1/esp32-isotp-ble-bridge 
* Tactrix OpenPort 2.0 J2534. Other J2534 devices are supported, but only if they support the STMIN_TX IOCTL. Clones and counterfeits have mixed results. Supported on Windows, possible to make work on Linux/OSX.
* SocketCAN on Linux, including MCP2517 Raspberry Pi Hats, slcan, and other interfaces. 

# Technical Information and Documentation

[docs/docs.md](docs/docs.md) contains detailed documentation about the Simos18 ECU architecture, boot, trust chain, and exploit process, including an exploit chain to enable unsigned code to be injected in ASW.

[docs/patch.md](docs/patch.md) and patch.bin provide a worked example of an ASW patch which "pivots" into an in-memory CBOOT with signature checking turned off (Sample Mode). This CBOOT will write the "Security Keys" / "OK Flags" for another arbitrary CBOOT regardless of signature validity, which will cause this final CBOOT to be "promoted" to the real CBOOT position by SBOOT. In this way a complete persistent trust chain bypass can be installed on a Simos18.1 ECU.

[docs/dsg.md](docs/dsg.md) documents the extremely simple protections applied for the Temic DQ250 DSG.

# Troubleshooting

Feel free to open a GitHub issue, but you MUST include the following 3 files if you want help:

`flash.log` , `flash_details.log`, and `udsoncan.log` . If you don't provide these 3 files (or you take phone pictures of your screen or some other ridiculous thing), I can't help you because I don't have information about what went wrong.

# Contributing

Pull Requests are welcome and appreciated. I will review them as I have time. Code is formatted using `black` - beyond this, there are limited code style and structure rules as the project is still evolving quickly. There are a few file preparation tests to verify basic file extraction and patching functionality, which you can run using python3 -munittest tests/test_prepare.py

# Tools

[VW_Flash.py](VW_Flash.py) provides a complete "port flashing" toolchain - it's a command line interface which has the capability of performing various operations, including fixing checksums for Application Software and Calibration blocks, fixing ECM2->ECM3 monitoring checksums for CAL, encrypting, compressing, and finally, flashing blocks to the ECU. [See the documentation here](docs/cli.md)

[VW_Flash_GUI.py](VW_Flash_GUI.py) provides a WXPython GUI for "simple" flashing of "flash package" containers, full BIN files, and calibration blocks. It also allows unlocking and FRF extraction. [See the documentation here](docs/windows.md)

[TC1791_CAN_BSL](https://github.com/bri3d/TC1791_CAN_BSL) and [Simos18_SBOOT](https://github.com/bri3d/Simos18_SBOOT) together form a complete "bench flashing" toolchain, including a password recovery exploit in SBOOT and a bootstrap loader with the ability to read/write/erase Flash.

[simos_hsl.py](https://github.com/joeFischetti/SimosHighSpeedLogger) , brought to you by `Joedubs`, provides a high-speed logger with support for various backends ($23 ReadMemoryByAddress, $2C DynamicallyDefineLocalIdentifier, and a proprietary $3E patch used by an aftermarket tool). All of these backends require application software patches. 

[sa2-seed-key](https://github.com/bri3d/sa2_seed_key) provides an implementation of the "SA2" Programming Session Seed/Key algorithm for VW Auto Group vehicles. The SA2 script can be found in the ODX flash container for the vehicle. The bytecode from the SA2 script is executed against the Security Access Seed to generate the Security Access Key. This script has been tested against a range of SA2 bytecodes and should be quite robust.

[extractodx.py](extractodx.py) extracts a factory Simos12/Simos18.1/Simos18.10 ODX container to decompressed, decrypted blocks suitable for modification and re-flashing. It supports the "AUDI AES" (0xA) encryption and "AUDI LZSS" (0xA) compression used in Simos ECUs, the DQ250-MQB/DQ400-MQB rolling substitution cipher, DQ500-0DL AES-128-CBC encryption, and unencrypted DQ500-0BH containers. Other ECUs use different flash container mechanisms within ODX files.

[frf](frf) provides an FRF flash container extractor. This should work to extract an ODX from any and all FRF flash containers as the format has not changed since it was introduced.

[a2l2xdf](https://github.com/bri3d/a2l2xdf) provides a method to extract specific definitions from A2L files and convert them to TunerPro XDF files. This is useful to 'cut down' an A2L file into something that's useful for tuning, and get it into a free tuning-focused UI. The `a2l2xdf.csv` in this directory provides a good "getting started" list of data to edit to prepare a basic Simos18.1 tune, as well.

The `lib/lzss` directory contains an implementation of LZSS modified to use the correction dictionary size and window length for Simos18 ECUs. Thanks to `tinytuning` for this.

# Supported ECUs

Each ECU family is a module in [lib/modules](lib/modules) selected by a matching CLI flag. Encryption/compression describe the flash-container format the tool handles for that ECU.

## Engine (Simos / Bosch)

| ECU | Flag | Encryption | Notes |
|-----|------|-----------|-------|
| Simos 8 / 8.5 | `--simos8` | XOR | S85 |
| Simos 10 | `--simos10` | XOR | SA |
| Simos 12 | `--simos12` | AES-128-CBC | SC1 |
| Simos 12.2 | `--simos122` | AES-128-CBC | SC2 |
| Simos 16 | `--simos16` | AES-128-CBC | SG1 |
| Simos 18.1/18.6 | `--simos18` | AES-128-CBC | SC8, unlock patch available |
| Simos 18.10 | `--simos1810` | AES-128-CBC | SCG, unlock patch available |
| Simos 18.41 | `--simos184` | AES-128-CBC | SCB |
| Bosch EDC17 | `--edc17` | Plaintext | generic EDC17 |
| Bosch EDC17C64 | `--edc17c64` | container | |
| Bosch MED17.5 | `--med175` | Plaintext | keyless CRC-32 integrity |
| Bosch MED17.5.2 | `--med1752` | Plaintext | |

## Transmissions (DSG / auto / AWD)

| ECU | Flag | Encryption | Compression | Notes |
|-----|------|-----------|-------------|-------|
| DQ250-MQB | `--dsg` | Rolling substitution cipher | LZSS10 | 256-byte key table |
| DQ200-MQB | `--dq200` | Rolling substitution cipher | LZSS10 | |
| DQ381-MQB | `--dq381` | AES-128-CBC | LZSS10 | Renesas SH-2A |
| DQ400-MQB | `--dq400` | Rolling substitution cipher | LZSS10 | different key table than DQ250 |
| DQ500-0BH | `--dq500` | None | None | Tiguan/Passat/Q3 |
| DQ500-0DL | `--dq500_0dl` | AES-128-CBC | LZSS10 | RS3/TTRS/RSQ3 |
| DL382 (0CK) | `--dl382` | None | LZSS10 (blocks 1/2) | Continental SH-2A, `EV_TCMDL382021` |
| DL501 (0B5) | — | Substitution cipher | LZSS10 | Audi longitudinal 7-speed |
| VL381 (0AW) | — | Substitution cipher | LZSS10 | Audi multitronic CVT |
| VL300 (01J) | — | SGO sum-substitution cipher (T1/T2) | None | Audi multitronic CVT (C167), unpack only: `unpack_vl300_sgo.py` |
| AL551 (ZF 8HP) | — | — | — | S-Tronic / Tiptronic |
| AL991 (0C8) | — | Plaintext | — | ZF 8HP |
| Haldex 4Motion | `--unsafe_haldex` | — | — | Gen 5 |

Unlock ("RSA-bypass") patches are provided for Simos 18.1/18.6 (SC8) and Simos 18.10 (SCG). Other Simos ECUs can be reflashed provided RSA validation (if present) has already been disabled.

## DL382 (0CK) — Continental/Temic

The DL382 `0CK` mechatronic is a Renesas SH-2A unit that identifies as `EV_TCMDL382021` — **not** the TriCore TC1784 "DL382" (Audi longitudinal, `8W_927155`), which is a separate ECU. Flash blocks are **not encrypted** and carry no RSA signature; the two large blocks are LZSS10-compressed, the two small ones stored plain. Invoke with `--dl382` (module `lib/modules/dl382.py`).

**Security access (UDS 0x27, SA2 script):** `6802814993A55A55AA4A05878105952668058249845AA5AA558703F78013` (a second SW variant ends the final EOR with `03F74321`).

**Flash blocks** (block id = ODX source-start-address):

| id | block | length | compression |
|----|-------|--------|-------------|
| 1 | DB_01 (ASW+CAL) | 0x1C0000 | LZSS10 |
| 2 | DB_02 | 0x40000 | LZSS10 |
| 3 | DB_03 | 0x8000 | none |
| 4 | DB_04 | 0x20000 | none |

**Block integrity:** each DATA block is verified by CRC-32 (4 bytes, over the uncompressed data). The ECU checks it via `RoutineControl 0x31 01 0202 <blockId>` after `RequestTransferExit`; a mismatch rejects the block. Like DQ381, the SH-2A bootloader performs a multi-phase block erase, so `erase_retries=5` is set.
