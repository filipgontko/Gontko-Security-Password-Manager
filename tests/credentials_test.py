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
        message = "Some of the attribute is not None."
        self.assertEquals(credentials.site, "google.com")
        self.assertEquals(credentials.username, "f1")
        self.assertEquals(credentials.password, "cucak")


if __name__ == '__main__':
    unittest.main()
