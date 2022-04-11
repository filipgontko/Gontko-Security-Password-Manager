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


if __name__ == '__main__':
    unittest.main()
