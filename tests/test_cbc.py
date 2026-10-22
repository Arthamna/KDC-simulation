import unittest

from crypto.cbc import decrypt_cbc, encrypt_cbc
from crypto.padding import pad, unpad


class CBCTests(unittest.TestCase):
    def test_roundtrip_ascii_and_multiblock(self):
        key, iv = b'abcdefghijklmnop', bytes(16)
        for plain in (b'', b'Hello, Bob!', b'1234567890abcdef', b'A longer ASCII message for CBC.'):
            self.assertEqual(decrypt_cbc(encrypt_cbc(plain, key, iv), key, iv), plain)

    def test_nist_cbc_first_block(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        self.assertEqual(encrypt_cbc(plain, key, iv)[:16].hex(), '7649abac8119b246cee98e9b12e9197d')

    def test_different_iv(self):
        key, plain = b'abcdefghijklmnop', b'hello'
        self.assertNotEqual(encrypt_cbc(plain, key, bytes(16)), encrypt_cbc(plain, key, b'\x01' * 16))

    def test_invalid_padding(self):
        with self.assertRaises(ValueError):
            unpad(b'1234567890abcde\x02')
        self.assertEqual(unpad(pad(b'hello')), b'hello')


if __name__ == '__main__':
    unittest.main()
