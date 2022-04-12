import unittest

from backend.databases.master_key_database import MasterKeyDB


class MasterKeyDBTestCase(unittest.TestCase):
    def test_create_table(self):
        master_key_database = MasterKeyDB()
        master_key_database.create_table()
        self.assertEqual(master_key_database.table, "master_table")

    def test_insert_master_information(self):
        pass

    def test_edit_master_information(self):
        pass

    def test_get_master_key_hash(self):
        pass

    def test_check_user_record_exists(self):
        pass

    def test_clear_table(self):
        master_key_database = MasterKeyDB()
        master_key_database.clear_table()
        self.assertEqual(master_key_database.connection, None)


if __name__ == '__main__':
    unittest.main()
