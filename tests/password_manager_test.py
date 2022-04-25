import unittest

from backend.password_manager import PasswordManager


class PasswordManagerTestCase(unittest.TestCase):
    def test_create_password_manager_instance(self):
        password_manager = PasswordManager()
        self.assertIsInstance(password_manager, PasswordManager)

    def test_sign_up(self):
        password_manager = PasswordManager()
        password_manager.sign_up()
        self.assertEqual(password_manager.user_logged_in, True)

    def test_check_user_exists(self):
        password_manager = PasswordManager()
        exists = password_manager.check_user_exists()
        self.assertEqual(exists, False)
        password_manager.sign_up()
        exists = password_manager.check_user_exists()
        self.assertEqual(exists, True)

    def test_login(self):
        password_manager = PasswordManager()
        password_manager.login()
        self.assertEqual(password_manager.user_logged_in, True)

    def test_logout(self):
        password_manager = PasswordManager()
        password_manager.user_logged_in = True
        password_manager.logout()
        self.assertEqual(password_manager.user_logged_in, False)

    def test_add_new_credentials(self):
        password_manager = PasswordManager()
        password_manager.login()
        result = password_manager.add_new_credentials()
        self.assertEqual(result, True)

    def test_edit_credentials(self):
        password_manager = PasswordManager()
        password_manager.login()
        result = password_manager.edit_credentials(switcher="password")
        self.assertEqual(result, True)

    def test_remove_credentials(self):
        password_manager = PasswordManager()
        password_manager.login()
        result = password_manager.remove_credentials()
        self.assertEqual(result, True)

    def test_get_credentials(self):
        password_manager = PasswordManager()
        password_manager.login()
        result = password_manager.get_all_credentials()
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
