import os
import random
import unittest
from pathlib import Path

from lib import lzss_zf
from lib.crypto.al551 import AL551

BIN = Path(__file__).resolve().parents[2] / "bin/dsg/AL551/4G0927158BD_1006.bin"


class TestLzssZf(unittest.TestCase):
    def roundtrip(self, data):
        packed = lzss_zf.compress(data)
        self.assertEqual(lzss_zf.decompress(packed, len(data)), data)
        return packed

    def test_synthetic(self):
        rnd = random.Random(1)
        self.roundtrip(b"")
        self.roundtrip(b"A")
        self.roundtrip(bytes(5000))
        self.roundtrip(bytes(rnd.randrange(256) for _ in range(5000)))
        self.roundtrip(bytes(rnd.choice(b"ABC\x00\xff") for _ in range(20000)))

    def test_rejects_bad_reference(self):
        # flag 0x80 -> first item is a token referencing before the start
        with self.assertRaises(ValueError):
            lzss_zf.decompress(bytes([0x80, 0x18, 0x03]), 6)

    def test_crypto_pipeline(self):
        crypto = AL551()
        data = os.urandom(1000) + bytes(3000)
        encoded = crypto.encrypt(crypto.compress(data))
        self.assertEqual(crypto.decompress(crypto.decrypt(encoded), len(data)), data)

    @unittest.skipUnless(BIN.exists(), "AL551 reference bin not present")
    def test_real_cal_block(self):
        cal = BIN.read_bytes()[0x180200:0x200000]
        packed = self.roundtrip(cal)
        self.assertLess(len(packed), len(cal))


if __name__ == "__main__":
    unittest.main()
