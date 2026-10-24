import json
import secrets
import string

from crypto.cbc import decrypt_cbc, encrypt_cbc

def ascii_key(text: str) -> bytes:
    key = text.encode('ascii')
    if len(key) != 16:
        raise ValueError('Key must contain exactly 16 ASCII characters')
    return key


def new_session_key() -> str:
    return ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))


def seal(payload: dict, key: str) -> dict:
    plaintext = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    iv = secrets.token_bytes(16)
    encrypted = encrypt_cbc(plaintext, ascii_key(key), iv)
    return {'iv': iv.hex(), 'ciphertext': encrypted.hex()}


def open_sealed(envelope: dict, key: str) -> dict:
    iv = bytes.fromhex(envelope['iv'])
    ciphertext = bytes.fromhex(envelope['ciphertext'])
    plaintext = decrypt_cbc(ciphertext, ascii_key(key), iv)
    result = json.loads(plaintext.decode('ascii'))
    if not isinstance(result, dict):
        raise ValueError('Expected encrypted JSON object')
    return result