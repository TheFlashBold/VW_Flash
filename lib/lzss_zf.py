"""LZSS variant used by ZF 8HPXY TCU flash blocks (AL551, ODX method "22").

Stream format:
    flag byte, bits consumed MSB first;
    bit 0 -> one literal byte;
    bit 1 -> big-endian u16 token: count = token >> 11 (5 bits, raw),
             distance = token & 0x7FF (11 bits, raw, 1..2047 back).

This differs from the DSG LZSS in extractodx.decompress_raw_lzss10 (6-bit count,
10-bit distance). Decoding an AL551 block with that one does not fail: Python's
negative indexing silently turns invalid back-references into garbage. The
decoder here is strict. Verified byte-exact: FD_4 of FL-4G0927158BD-1006.frf
equals an OBD CAL read of that version.
"""

MAX_DIST = 0x7FF
MAX_COUNT = 0x1F
MIN_MATCH = 3  # a 2-byte token only pays off from 3 bytes on


def decompress(data: bytes, size: int) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while len(out) < size and i < n:
        flags = data[i]
        i += 1
        for bit in range(7, -1, -1):
            if len(out) >= size or i >= n:
                break
            if not (flags >> bit) & 1:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= n:
                raise ValueError(f"truncated token at input {i:#x}")
            token = (data[i] << 8) | data[i + 1]
            i += 2
            count, dist = token >> 11, token & MAX_DIST
            if dist == 0 or dist > len(out):
                raise ValueError(f"bad back-reference dist={dist:#x} at output {len(out):#x}")
            for _ in range(count):
                out.append(out[-dist])
    if len(out) != size:
        raise ValueError(f"decompressed {len(out):#x} bytes, expected {size:#x}")
    return bytes(out)


def compress(data: bytes) -> bytes:
    """Greedy compressor producing a stream `decompress` accepts.

    Not byte-identical to ZF's own compressor; the output is only guaranteed to
    round-trip.
    """
    out = bytearray()
    heads = {}  # 3-byte prefix -> recent positions
    i, n = 0, len(data)
    while i < n:
        flag_pos = len(out)
        out.append(0)
        flags = 0
        for bit in range(7, -1, -1):
            if i >= n:
                break
            best_len = best_dist = 0
            if i + MIN_MATCH <= n:
                for j in reversed(heads.get(data[i:i + MIN_MATCH], ())):
                    dist = i - j
                    if dist > MAX_DIST:
                        break
                    length = 0
                    while length < MAX_COUNT and i + length < n and data[j + length] == data[i + length]:
                        length += 1
                    if length > best_len:
                        best_len, best_dist = length, dist
                        if length == MAX_COUNT:
                            break
            step = best_len if best_len >= MIN_MATCH else 1
            if step > 1:
                flags |= 1 << bit
                token = (best_len << 11) | best_dist
                out += bytes((token >> 8, token & 0xFF))
            else:
                out.append(data[i])
            for k in range(i, i + step):
                if k + MIN_MATCH <= n:
                    lst = heads.setdefault(data[k:k + MIN_MATCH], [])
                    lst.append(k)
                    if len(lst) > 64:
                        del lst[:32]
            i += step
        out[flag_pos] = flags
    return bytes(out)
