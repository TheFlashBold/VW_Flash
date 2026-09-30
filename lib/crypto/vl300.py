import pathlib
from lib.constants import internal_path
from lib.crypto.crypto_interface import CryptoInterface

# Audi Multitronic VL300 (01J, Temic, C167) "SGML Object File" (.sgo) cipher.
#
# Software part numbers 8E0/8E1/8E3/8E4/8E5/4E0/4E1/4E2/4F0/4F1/4F2/4F5/4F9
# 910155/156/157/159 (single block, flash 0x8000 len 0x78000).  Same SGO
# container as the pre-MQB DQ250 (see dsg_premqb.py), but a much simpler cipher:
# a substitution on the sum of the current and the previous ciphertext byte.
#
#     decrypt:  p[i]      = T[(c[i] + c[i-1]) & 0xFF]        IV c[-1] = 0xFF
#     encrypt:  c[i]      = (Tinv[p[i]] - c[i-1]) & 0xFF
#
# (Equivalent to c[i] - c[i-2] = E[p[i]] - E[p[i-1]], i.e. constant plaintext
# runs give a period-2 ciphertext -- the tell-tale "c2dd c2dd ..." pattern.)
#
# T is a 256-byte permutation; two generations exist:
#   T1: A4 8E (8E0/8E1/8E3/8E4/8E5) + early 4E1/4E2/4F0910157K/4F1910155C.
#       Recovered from 8E0910159B__0020 <-> "VAG Temic VL300 - Original.ols"
#       (0x78000 image, same build "VL300 10.09.04 09:16:18"), 96% byte match,
#       the rest genuine data differences.
#   T2: A6 4F (4F1/4F2/4F5/4F9), 4E0910155Q, 4E1910155C.  Recovered by aligning
#       against T1-decoded siblings of the same build (4F1910155D<->8E1910155D,
#       4E0910155Q<->8E3910155P); every entry verified by context agreement.
# The tables are auto-selected by the "VL300 Standard" identity string.

IV = 0xFF
TABLES = ("1", "2")


class VL300(CryptoInterface):
    def __init__(self, table: str = "1"):
        self.t = pathlib.Path(internal_path("data", f"vl300_sgo_T{table}.bin")).read_bytes()
        self.table = table

    def decrypt(self, data: bytes) -> bytes:
        t = self.t
        prev = IV
        out = bytearray(len(data))
        for i, c in enumerate(data):
            out[i] = t[(c + prev) & 0xFF]
            prev = c
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        tinv = [0] * 256
        for s, p in enumerate(self.t):
            tinv[p] = s
        prev = IV
        out = bytearray(len(data))
        for i, p in enumerate(data):
            prev = out[i] = (tinv[p] - prev) & 0xFF
        return bytes(out)
