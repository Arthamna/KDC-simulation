"""AES-128 block cipher, implemented directly from FIPS 197."""


def gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return result


def _rot(value: int, n: int) -> int:
    return ((value << n) | (value >> (8 - n))) & 0xFF


def _inverse(value: int) -> int:
    if value == 0:
        return 0
    result, power = 1, value
    for bit in (128, 64, 32, 16, 8, 4, 2, 1):
        if 254 & bit:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
    return result


def _sub_byte(value: int) -> int:
    value = _inverse(value)
    return value ^ _rot(value, 1) ^ _rot(value, 2) ^ _rot(value, 3) ^ _rot(value, 4) ^ 0x63


SBOX = [_sub_byte(i) for i in range(256)]
INV_SBOX = [0] * 256
for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


def expand_key(key: bytes) -> list[bytes]:
    """Return eleven 16-byte round keys (AES-128)."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[-1][:]
        if i % 4 == 0:
            temp = [SBOX[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        words.append([x ^ y for x, y in zip(words[i - 4], temp)])
    return [bytes(sum(words[4 * round_:4 * round_ + 4], [])) for round_ in range(11)]
