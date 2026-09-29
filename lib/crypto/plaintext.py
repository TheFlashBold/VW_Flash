from lib.crypto.crypto_interface import CryptoInterface


class PlaintextCrypto(CryptoInterface):
    """Identity codec for ECUs that flash plaintext blocks.

    Bosch MEDC17 Gen1 (MED17.5/.1/.2/.5) stores and transfers flash blocks in
    the clear: no AES, no RSA signature. Block integrity is a keyless CRC-32
    only (see med175 module notes). Encrypt/decrypt are therefore no-ops.
    """

    def decrypt(self, data: bytes) -> bytes:
        return bytes(data)

    def encrypt(self, data: bytes) -> bytes:
        return bytes(data)
