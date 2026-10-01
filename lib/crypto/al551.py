from lib import lzss_zf
from lib.crypto.crypto_interface import CryptoInterface


class AL551(CryptoInterface):
    """ZF gen2 8HPXY TCU (AL551 / EV_TCMAL551, ZX8U, SH-2A big-endian).

    FRF flash blocks use ENCRYPT-COMPRESS-METHOD "22": the plaintext is
    compressed with the ZF LZSS variant (5-bit count / 11-bit distance, see
    lib/lzss_zf.py) and then XORed with a fixed, repeating 19-byte ASCII key.
    This is NOT AES and NOT the DSG progressive-substitution cipher used by the
    DSG TCUs (the AES S-boxes present in the AL551 bootloader are used elsewhere).

    Decode pipeline (see extractodx.py): crypto.decrypt() undoes the XOR layer,
    then crypto.decompress() (lzss_zf, strict) expands the stream to the
    declared UNCOMPRESSED-SIZE. The DSG LZSS10 decoder must NOT be used here.

    The key was recovered by known-plaintext: XORing an FRF block against the
    compressed form of the corresponding decrypted-flash region exposes a
    cleanly repeating 19-byte keystream, "CyA2008ZFVAGtcuxsam".
    """

    KEY = b"CyA2008ZFVAGtcuxsam"

    def _xor(self, data: bytes) -> bytes:
        k = self.KEY
        n = len(k)
        return bytes(data[i] ^ k[i % n] for i in range(len(data)))

    # XOR is its own inverse; encrypt and decrypt are the same transform.
    def decrypt(self, data: bytes) -> bytes:
        return self._xor(data)

    def encrypt(self, data: bytes) -> bytes:
        return self._xor(data)

    # Block codec for ENCRYPT-COMPRESS-METHOD "22" (used by extractodx.extract_odx).
    def decompress(self, data: bytes, size: int) -> bytes:
        return lzss_zf.decompress(data, size)

    def compress(self, data: bytes) -> bytes:
        return lzss_zf.compress(data)
