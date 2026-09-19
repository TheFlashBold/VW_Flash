import pathlib
from lib.constants import internal_path

# Pre-MQB DQ250 (02E, Temic) DSG "SGML Object File" (.sgo) cipher.
#
# This is the older sibling of the MQB substitution cipher in dsg.py.  Both are
# rolling / self-synchronising substitution ciphers with an accumulating 8-bit
# offset, but the pre-MQB variant differs in two ways:
#
#   * it uses TWO distinct 256-byte permutation tables -- one for the
#     substitution (ksub) and one for the rolling key stream (kroll) -- whereas
#     the MQB cipher reuses a single table for both, and
#   * the offset update SUBTRACTS the plaintext terms instead of adding them.
#
# Decrypt (data = ciphertext block, out = plaintext byte):
#     out       = ksub[(cipher[i] + offset) & 0xFF]
#     offset    = (offset - out - last_out + kroll[(roll >> 8) & 0xFF]) & 0xFF
#     roll     += 0x167          # advanced BEFORE first use (roll starts 0)
#     last_out  = out
# offset starts at 0, last_out starts at 0.
#
# The tables are per-platform.  Table "A" (default) covers the later 02E
# generation: SW families 0692-0695, 0698, 0699 and the 4-char families
# (e.g. v069K7...).  Recovered from the exact pair
#     v0698x3402ec getriebe DSG MP8x F93S  <->  02E300057A_9334.bin
# via a 49184-byte plaintext 0x00 run (gives kroll) + offset propagation
# (gives ksub); self-decrypts that block 100% (720896/720896).

ROLL_INC = 0x167


class DSGPreMQB:
    def __init__(self, table: str = "A"):
        self.ksub = list(
            pathlib.Path(internal_path("data", f"dq250_premqb_dsg_ksub_{table}.bin")).read_bytes()
        )
        self.kroll = list(
            pathlib.Path(internal_path("data", f"dq250_premqb_dsg_kroll_{table}.bin")).read_bytes()
        )

    def decrypt(self, data: bytes) -> bytes:
        ksub, kroll = self.ksub, self.kroll
        off = 0
        last = 0
        roll = 0
        out = bytearray(len(data))
        for i in range(len(data)):
            roll += ROLL_INC
            p = ksub[(data[i] + off) & 0xFF]
            out[i] = p
            off = (off - p - last + kroll[(roll >> 8) & 0xFF]) & 0xFF
            last = p
        return bytes(out)
