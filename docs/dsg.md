
The DQ250-MQB DSG is fairly unprotected - [a simple 256-byte rolling-offset substitution cipher](https://github.com/bri3d/VW_Flash/blob/master/lib/crypto/dsg.py) encrypts an LZSS compressed payload, and the controller will even accept uncompressed, unencrypted payloads as well. [Checksums are just JAMCRC / inverse CRC32 at the end of a file](https://github.com/bri3d/VW_Flash/blob/master/lib/dsg_checksum.py) .

A small flash driver module is uploaded as part of DQ250 flashing, which is protected only by an external checksum. This also allows for some clever payloads to be uploaded and used to dump DSG memory.

The Driver is uploaded to `0xD4000000` (Scratchpad RAM), and the first 4 bytes are checked and must be `00 00 2E A2` . Next, the full Driver's checksum must match the CRC32 sent in the UDS Checksum request.

When the Checksum request for the Driver block is invoked, the pointer at `0x4` in the Driver is read and executed - by default, the function at `d4000300` (`0x300` in the Driver). This can be trivially replaced with any custom code as desired, for example a Flash read primitive to dump/backup DSG firmware.

DQ200 MQB uses the same split between an external Driver CRC32 and internal
little-endian JAMCRC values at the end of CAL and ASW. Two Driver generations
are used by the available 0CW software:

| Generation | First 4 Driver bytes | External CRC32 for the stock Driver | ASW length |
|---|---:|---:|---:|
| 06/09 | `01 00 00 9D` | `80 86 18 1B` | `0x100000` |
| Later | `00 00 2E A2` | `F9 74 17 6E` | `0x130000` |

The Driver CRC32 is calculated from the complete uncompressed Driver and sent
big-endian in UDS routine `0x0202`; it is not stored at the end of the Driver.
CAL is always `0x20000` bytes. The DQ200 CBOOT implementation verifies the
Driver separately, while CAL/ASW keep their JAMCRC in their final four bytes.
