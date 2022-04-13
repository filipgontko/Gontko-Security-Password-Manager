import unittest

from backend.crypto import create_master_key
from backend.databases.master_key_database import MasterKeyDB


class MasterKeyDBTestCase(unittest.TestCase):
    def test_create_table(self):
        master_key_database = MasterKeyDB()
        master_key_database.create_table()
        self.assertEqual(master_key_database.table, "master_table")

    def test_insert_and_get_master_information(self):
        master_key_database = MasterKeyDB()
        hashed_master_key = create_master_key()
        master_key_database.insert_master_information(hashed_master_key, "abc@dgef.com")
        get_master_key_hash = master_key_database.get_master_key_hash("abc@dgef.com")
        self.assertEqual(hashed_master_key, get_master_key_hash)

    def test_edit_master_information(self):
        master_key_database = MasterKeyDB()
        new_master_key = create_master_key()
        master_key_database.edit_master_information("abc@dgef.com", new_master_key)
        get_master_key_hash = master_key_database.get_master_key_hash("abc@dgef.com")
        self.assertEqual(new_master_key, get_master_key_hash)

    def test_check_user_record_exists(self):
        master_key_database = MasterKeyDB()
        exists = master_key_database.check_user_record_exists("abc@dgef.com")
        self.assertEqual(True, exists)

    def test_check_user_record_not_exists(self):
        master_key_database = MasterKeyDB()
        not_exists = master_key_database.check_user_record_exists("trefa@dgef.com")
        self.assertEqual(False, not_exists)

    def test_clear_table(self):
        master_key_database = MasterKeyDB()
        master_key_database.clear_table()
        self.assertEqual(master_key_database.connection, None)


if __name__ == '__main__':
    unittest.main()
