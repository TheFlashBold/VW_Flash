from lib.crypto.crypto_interface import CryptoInterface
import pathlib
from lib.constants import internal_path

# This is a progressive substitution cypher
# The code for this can be found at 0x800164AC and the key material at 0x8001053C in flash from DQ250_MQB_0D9300012L_4516
# A rolling key offset is maintained which incorporates the encrypted data stream, the previous byte in the data stream, and a rolling stream of the key data incremented by 0x167.
# This rolling offset is combined with the actual data value, which is then used as an index into a 256-byte substitution table.


class DSG(CryptoInterface):
    def __init__(self, key_name: str = "mqb_dsg_key.bin"):
        # Newer DQ200 (0CW) mechatronic gen uses a different 256-byte table:
        # pass key_name="mqb_dsg_key_gen2.bin". Default = original DQ250/DQ200 table.
        self.key_name = key_name

    def decrypt(self, data: bytes):
        dsg_key = internal_path("data", self.key_name)
        dsg_key_bytes = pathlib.Path(dsg_key).read_bytes()
        counter = 0
        offset = 0
        rolling_stream_offset = 0
        last_data = 0
        output_data = []
        while counter < len(data):
            cipher_data = dsg_key_bytes[data[counter] + offset & 0xFF]
            offset += cipher_data
            offset += last_data
            rolling_stream_offset += 0x167
            offset += dsg_key_bytes[(rolling_stream_offset >> 8) & 0xFF]
            last_data = cipher_data
            output_data.append(cipher_data)
            counter += 1
        return bytes(output_data)

    def encrypt(self, data: bytes):
        dsg_key = internal_path("data", self.key_name)
        dsg_key_bytes = pathlib.Path(dsg_key).read_bytes()
        counter = 0
        offset = 0
        rolling_stream_offset = 0
        last_data = 0
        output_data = []
        while counter < len(data):
            data_byte = data[counter]
            match_index = dsg_key_bytes.index(data_byte)
            cipher_data = match_index - offset & 0xFF
            offset += data_byte
            offset += last_data
            rolling_stream_offset += 0x167
            offset += dsg_key_bytes[(rolling_stream_offset >> 8) & 0xFF]
            last_data = data_byte
            output_data.append(cipher_data)
            counter += 1
        return bytes(output_data)
