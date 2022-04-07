import unittest
from backend.credetntials import *


class CredentialsTest(unittest.TestCase):
    def test_is_valid_credentials_instance(self):
        credentials = Credentials()
        message = "Given object is not instance of Credentials."
        self.assertIsInstance(credentials, Credentials, message)

    def test_create_credentials_instance(self):
        credentials = Credentials()
        message = "Some of the attribute is not None."
        self.assertIsNone(credentials.site, message)
        self.assertIsNone(credentials.username, message)
        self.assertIsNone(credentials.password, message)

    def test_create_not_empty_credentials(self):
        credentials = Credentials("google.com", "f1", "cucak")
        self.assertEqual(credentials.site, "google.com")
        self.assertEqual(credentials.username, "f1")
        self.assertEqual(credentials.password, "cucak")

    def test_get_credentials(self):
        credentials = Credentials("google.com", "f1", "cucak")
        message = "Get credentials didn't return list of credentials."
        self.assertEqual(credentials.get_credentials(), ["google.com", "f1", "cucak"], message)

    def test_update_site(self):
        credentials = Credentials("google.com", "f1", "cucak")
        credentials.update_site("f1.com")
        message = "Get credentials didn't return updated list of credentials."
        self.assertEqual(credentials.get_credentials(), ["f1.com", "f1", "cucak"], message)

    def test_update_username(self):
        credentials = Credentials("google.com", "f1", "cucak")
        credentials.update_username("redbull")
        message = "Get credentials didn't return updated list of credentials."
        self.assertEqual(credentials.get_credentials(), ["google.com", "redbull", "cucak"], message)

    def test_update_password(self):
        credentials = Credentials("google.com", "f1", "cucak")
        credentials.update_password("verstappen")
        message = "Get credentials didn't return updated list of credentials."
        self.assertEqual(credentials.get_credentials(), ["google.com", "f1", "verstappen"], message)

    def test_remove_credentials(self):
        pass


if __name__ == '__main__':
    unittest.main()
