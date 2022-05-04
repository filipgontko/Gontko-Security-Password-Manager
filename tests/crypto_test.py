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

    def test_encrypt_and_decrypt_message(self):
        message = "password115468481121684"
        encrypted_message = encrypt_message(message)
        decrypted = decrypt_message(encrypted_message)
        self.assertEqual(decrypted, "password115468481121684")

    def test_hash_key(self):
        stored_hashed_key = create_master_key()
        self.assertEqual(stored_hashed_key, compare_master_password_hash())

    def test_generate_password(self):
        generated_password = generate_password(otp=Optional)
        self.assertEqual(len(generated_password), 12)


if __name__ == '__main__':
    unittest.main()
