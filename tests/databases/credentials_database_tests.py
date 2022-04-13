import unittest

from backend.credentials import Credentials
from backend.crypto import decrypt_message
from backend.databases.credentials_database import CredentialsDB


class CredentialsDBTestCase(unittest.TestCase):
    def test_create_table(self):
        credentials_database = CredentialsDB()
        credentials_database.create_table()
        self.assertEqual(credentials_database.table, "credentials_table")

    def test_insert_and_get_credentials(self):
        credentials_database = CredentialsDB()
        credentials = Credentials("google.com", "goofy", "password")
        credentials_database.insert_credentials(credentials)
        get_password = credentials_database.get_password(credentials)
        decrypted = decrypt_message(get_password)
        self.assertEqual("password", decrypted)

    def test_edit_password(self):
        credentials_database = CredentialsDB()
        credentials = Credentials("google.com", "goofy", "new_password")
        credentials_database.edit_password(credentials)
        get_password = credentials_database.get_password(credentials)
        decrypted = decrypt_message(get_password)
        self.assertEqual("new_password", decrypted)

    def test_view_credentials(self):
        credentials_database = CredentialsDB()
        self.assertEqual(credentials_database.view_credentials(), [("google.com", "goofy")])

    def test_delete_credentials(self):
        credentials_database = CredentialsDB()
        credentials = Credentials("google.com", "goofy")
        credentials_database.delete_credentials(credentials)
        self.assertEqual(credentials_database.view_credentials(), [])

    def test_clear_table(self):
        credentials_database = CredentialsDB()
        credentials_database.clear_table()
        self.assertEqual(credentials_database.connection, None)

    def test_drop_table(self):
        credentials_database = CredentialsDB()
        credentials_database.drop_table()
        self.assertEqual(credentials_database.connection, None)


if __name__ == '__main__':
    unittest.main()
