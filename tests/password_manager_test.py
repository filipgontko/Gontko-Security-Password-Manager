import unittest

from backend.password_manager import PasswordManager


class PasswordManagerTestCase(unittest.TestCase):
    def test_create_password_manager_instance(self):
        password_manager = PasswordManager()
        self.assertIsInstance(password_manager, PasswordManager)


if __name__ == '__main__':
    unittest.main()
