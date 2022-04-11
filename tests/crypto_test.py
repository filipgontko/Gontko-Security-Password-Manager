import unittest

from backend.crypto import *


class CryptoTestCase(unittest.TestCase):
    def test_key_exists(self):
        if os.path.isfile('secret.key'):
            os.remove('secret.key')
        self.assertEqual(key_exists(), False)

    def test_generate_crypto_base(self):
        generate_crypto_key_base()
        self.assertEqual(key_exists(), True)

    def test_load_crypto_key_base_from_file(self):
        pass

    def test_get_crypto_key(self):
        pass

    def test_encrypt_message(self):
        pass

    def test_decrypt_message(self):
        pass

    def test_has_key(self):
        pass

    def test_generate_password(self):
        pass

if __name__ == '__main__':
    unittest.main()
