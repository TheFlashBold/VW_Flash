from lib.crypto.crypto_interface import CryptoInterface

# Bosch EDC17 (newer ASAM ODX-F containers, e.g. EDC17C64 / 04L906021*) protect
# each flash block with a trivial repeating-XOR keystream in addition to the
# outer FRF "recursive XOR" cipher. In the ODX <ENCRYPT-COMPRESS-METHOD> byte
# (e.g. "A1") the second character selects this scheme ("1"), the first selects
# the compression ("A" = LZSS10). This is NOT AES -- unlike Simos, where the
# same "1" position would map to an AES key.
#
# The key "BiWbBuD101" is the community-known repeating key also used by the
# older bracket-text BCB streams (see extract_frf_edc17.py KNOWN_KEYS).


class Edc17RepeatingXor(CryptoInterface):
    def __init__(self, key: bytes = b"BiWbBuD101"):
        self.key = key

    def decrypt(self, data: bytes) -> bytes:
        k = self.key
        kl = len(k)
        return bytes(b ^ k[i % kl] for i, b in enumerate(data))

    def encrypt(self, data: bytes) -> bytes:
        # XOR is symmetric.
        return self.decrypt(data)
