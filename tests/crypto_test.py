import unittest

from backend.crypto import *


class CryptoTestCase(unittest.TestCase):
    def test_key_exists(self):
        self.assertEqual(key_exists(), True)

    def test_generate_crypto_base(self):
        generate_crypto_key_base()
        self.assertEqual(key_exists(), True)

    def test_load_crypto_key_base_from_file(self):
        key_base = load_crypto_key_base_from_file()
        self.assertEqual(key_base, "u7C2XipBwEMom|L80Z;t,1#>-")

    def test_encrypt_message(self):
        message = "password11"
        encrypted_message = encrypt_message(message)
        self.assertEqual(encrypted_message, True)

    def test_decrypt_message(self):
        decrypted = decrypt_message("encrypted_message.bin")
        self.assertEqual(decrypted, "password11")

    def test_has_key(self):
        pass

    def test_generate_password(self):
        pass


if __name__ == '__main__':
    unittest.main()
