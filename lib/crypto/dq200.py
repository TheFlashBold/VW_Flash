from lib.crypto.crypto_interface import CryptoInterface


# DQ200 MQB 0CW ODX method-11 key tables.
#
# The decrypt routine is the same progressive substitution cipher used by
# DQ250/DQ400. The early 0CW300041E micro contains the routine at 0x80015968
# and the early table at 0x800169a0. The late table was recovered from a
# complete 0CW300045L-4530 CAL known-plaintext pair and validates against
# DB_2/3/4.
DQ200_MQB_EARLY_KEY = bytes.fromhex(
    "b0fbc45de4cc4d121779b5c963820ea0"
    "7c9fc1a74002c84590dc1ed75f227499"
    "089126cae5f06d0b1d95d609bd2af35b"
    "b150aec6a81f922459e8e36b163f7821"
    "7b5af627054c653e76abdd859b753052"
    "0c131cbf0fceb86c67e223a64a6f9eee"
    "9355b984dfdeecbed343d219acaaa31b"
    "3456f74f18b77adac0d8c55106f5fa4e"
    "9670680a2ea43cd042cffff2bc862894"
    "2b32eac20166f9ad36e060629d00a2cd"
    "bb115c8714afc7737f4647fcf1b477d9"
    "a18df4cb07353983eb800d44fe413a9c"
    "4964d5726aef58d18fc3312d20892ce9"
    "88a58b7e25572f33f88e61d4154b10e7"
    "5e69b6dbe6ed4897b2378a5438988c29"
    "9ae103048153fd6e71ba3d7d3ba9b31a"
)

DQ200_MQB_LATE_KEY = bytes.fromhex(
    "be0eb8584ce6ead4e9223e002801cad3"
    "7c66dd041e9398492131ebb0380b82ba"
    "571516f330ac8f1467797513331a0581"
    "b3f0703c642f17f9d62cda6fc3bd6072"
    "40facc07363a4d4255a7c2eee5c05c41"
    "201d0a926e5e459761e3abbc9cd0068e"
    "ad9f8a73ed77445ab1194a630f2dff9a"
    "39f46c90592e53a8629b5ffe2bfd2978"
    "4e8d37e27f02b7d2decb7eae52e8fb80"
    "2aef0d4fec5b468c7b832748517a096a"
    "23266da9c8b5108b0887aa1256c1346b"
    "183f886965afd885df9de01cb9d7a51f"
    "c5991143dba6f53591e11be7f25095bb"
    "a371b2c6ce9e3d3b47dc84c47df7f15d"
    "68b40cc9d1f85489f6fc0374cdcfd9d5"
    "86b6bf76a424a196a2e494c7a04b2532"
)

DQ200_MQB_KEYS = {
    "late": DQ200_MQB_LATE_KEY,
    "early": DQ200_MQB_EARLY_KEY,
}


class DQ200(CryptoInterface):
    def __init__(self, key: bytes | str = DQ200_MQB_LATE_KEY):
        if isinstance(key, str):
            key = DQ200_MQB_KEYS[key]
        if len(key) != 256 or len(set(key)) != 256:
            raise ValueError("DQ200 key must be a 256-byte permutation")
        self.key = key

    def decrypt(self, data: bytes):
        offset = 0
        rolling_stream_offset = 0
        last_data = 0
        output_data = []
        for data_byte in data:
            plain_data = self.key[data_byte + offset & 0xFF]
            offset += plain_data
            offset += last_data
            rolling_stream_offset += 0x167
            offset += self.key[(rolling_stream_offset >> 8) & 0xFF]
            last_data = plain_data
            output_data.append(plain_data)
        return bytes(output_data)

    def encrypt(self, data: bytes):
        offset = 0
        rolling_stream_offset = 0
        last_data = 0
        output_data = []
        for data_byte in data:
            match_index = self.key.index(data_byte)
            cipher_data = match_index - offset & 0xFF
            offset += data_byte
            offset += last_data
            rolling_stream_offset += 0x167
            offset += self.key[(rolling_stream_offset >> 8) & 0xFF]
            last_data = data_byte
            output_data.append(cipher_data)
        return bytes(output_data)
