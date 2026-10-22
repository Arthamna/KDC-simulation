import unittest

from crypto.aes import decrypt_block, encrypt_block, expand_key


class AESTests(unittest.TestCase):
    def test_nist_aes128_vector(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex('00112233445566778899aabbccddeeff')
        expected = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        self.assertEqual(encrypt_block(plain, key), expected)
        self.assertEqual(decrypt_block(expected, key), plain)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            expand_key(b'too short')

    def test_ascii_key_roundtrip(self):
        key = b'abcdefghijklmnop'
        plain = b'Hello AES-128!!!'
        self.assertEqual(decrypt_block(encrypt_block(plain, key), key), plain)


if __name__ == '__main__':
    unittest.main()
