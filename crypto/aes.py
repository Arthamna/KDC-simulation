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
    result, power, exponent = 1, value, 254
    while exponent:
        if exponent & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        exponent >>= 1
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


def _add_round_key(state: list[int], key: bytes) -> None:
    for i, byte in enumerate(key):
        state[i] ^= byte


def _shift_rows(state: list[int]) -> None:
    for row in range(1, 4):
        values = [state[row + 4 * col] for col in range(4)]
        values = values[row:] + values[:row]
        for col, value in enumerate(values):
            state[row + 4 * col] = value


def _mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a, b, c, d = state[i:i + 4]
        state[i:i + 4] = [
            gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d,
            a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d,
            a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3),
            gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2),
        ]


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block using AES-128."""
    if len(plaintext) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    round_keys = expand_key(key)
    state = list(plaintext)
    _add_round_key(state, round_keys[0])
    for round_ in range(1, 10):
        state = [SBOX[x] for x in state]
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_])
    state = [SBOX[x] for x in state]
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state)


def _inv_shift_rows(state: list[int]) -> None:
    for row in range(1, 4):
        values = [state[row + 4 * col] for col in range(4)]
        values = values[-row:] + values[:-row]
        for col, value in enumerate(values):
            state[row + 4 * col] = value


def _inv_mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a, b, c, d = state[i:i + 4]
        state[i:i + 4] = [
            gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(c, 13) ^ gf_mul(d, 9),
            gf_mul(a, 9) ^ gf_mul(b, 14) ^ gf_mul(c, 11) ^ gf_mul(d, 13),
            gf_mul(a, 13) ^ gf_mul(b, 9) ^ gf_mul(c, 14) ^ gf_mul(d, 11),
            gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(c, 9) ^ gf_mul(d, 14),
        ]


def decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt a single 16-byte block using AES-128."""
    if len(ciphertext) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    round_keys = expand_key(key)
    state = list(ciphertext)
    _add_round_key(state, round_keys[10])
    for round_ in range(9, 0, -1):
        _inv_shift_rows(state)
        state = [INV_SBOX[x] for x in state]
        _add_round_key(state, round_keys[round_])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    state = [INV_SBOX[x] for x in state]
    _add_round_key(state, round_keys[0])
    return bytes(state)
