import unittest
import sqlite3

from backend.databases.database import Database
from backend.my_logger import logger


class DatabaseTestCase(unittest.TestCase):
    def test_connect_and_disconnect_db(self):
        database = Database()
        conn = database.connect_db()
        self.assertEqual(conn, database.connection)
        conn = database.disconnect_db()
        self.assertEqual(conn, database.connection)

    def test_create_table(self):
        database = Database()
        try:
            database.connect_db()
            cursor = database.connection.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS test_table (
                        test TEXT,
                        test2 TEXT
                        );"""
            cursor.execute(create_table_query)
            database.connection.commit()
            cursor.close()
            database.table = "test_table"
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            database.disconnect_db()
        self.assertEqual(database.table, "test_table")

    def test_clear_table(self):
        database = Database()
        database.clear_table("test_table")
        self.assertEqual(database.connection, None)


if __name__ == '__main__':
    unittest.main()
