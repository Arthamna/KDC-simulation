"""PKCS#7 padding for a 16-byte AES block."""


def pad(data: bytes) -> bytes:
    count = 16 - len(data) % 16
    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("Invalid PKCS#7 block length")
    count = data[-1]
    if count < 1 or count > 16 or data[-count:] != bytes([count]) * count:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-count]
