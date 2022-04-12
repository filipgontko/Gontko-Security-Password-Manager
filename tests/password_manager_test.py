import unittest

from backend.password_manager import PasswordManager


class PasswordManagerTestCase(unittest.TestCase):
    def test_create_password_manager_instance(self):
        password_manager = PasswordManager()
        self.assertIsInstance(password_manager, PasswordManager)

    def test_sign_up(self):
        pass

    def test_check_user_exists(self):
        pass

    def test_login(self):
        pass

    def test_logout(self):
        pass

    def test_user_logged_in(self):
        pass

    def test_add_new_credentials(self):
        pass

    def test_edit_credentials(self):
        pass

    def test_remove_credentials(self):
        pass

    def test_prepare_credentials(self):
        pass


if __name__ == '__main__':
    unittest.main()
