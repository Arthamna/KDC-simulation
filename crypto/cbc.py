"""Manual AES-128-CBC. Caller supplies a fresh 16-byte IV for each message."""

from crypto.aes import decrypt_block, encrypt_block
from crypto.padding import pad, unpad


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("CBC IV must be 16 bytes")
    previous = iv
    output = bytearray()
    padded = pad(plaintext)
    for offset in range(0, len(padded), 16):
        block = padded[offset:offset + 16]
        previous = encrypt_block(_xor(block, previous), key)
        output.extend(previous)
    return bytes(output)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise ValueError("Invalid CBC IV or ciphertext length")
    previous = iv
    output = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        output.extend(_xor(decrypt_block(block, key), previous))
        previous = block
    return unpad(bytes(output))
