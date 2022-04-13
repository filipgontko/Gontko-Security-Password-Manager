import unittest

from backend.credentials import Credentials
from backend.crypto import encrypt_message
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
        self.assertEqual("encrypted", get_password)

    def test_edit_password(self):
        credentials_database = CredentialsDB()

    def test_get_password(self):
        credentials_database = CredentialsDB()

    def test_delete_credentials(self):
        credentials_database = CredentialsDB()

    def test_clear_table(self):
        master_key_database = CredentialsDB()
        master_key_database.clear_table()
        self.assertEqual(master_key_database.connection, None)


if __name__ == '__main__':
    unittest.main()
