from lib.crypto.crypto_interface import CryptoInterface
import Crypto.Cipher.AES


class AES(CryptoInterface):
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt bytes to bytes using AES"""
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CBC, self.iv)
        return cipher.decrypt(data)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt bytes to bytes using AES"""
        remainder = len(data) % 16
        if remainder:
            data = data + b"\x00" * (16 - remainder)
        cipher = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CBC, self.iv)
        return cipher.encrypt(data)
