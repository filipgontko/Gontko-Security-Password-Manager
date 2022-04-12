import sqlite3

from abc import ABC, abstractmethod
from backend.my_logger import logger


class Database(ABC):
    def __init__(self, connection=None):
        self.connection = connection

    def create_table(self, table_name):
        """
        Create table for storing username, password and site.
        :return: bool: True if successful, False otherwise.
        """
        try:
            sqlite_conn = self.connect_db()
            cursor = sqlite_conn.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS {} (
                            site TEXT,
                            username TEXT,
                            password TEXT
                            );""".format(table_name)
            cursor.execute(create_table_query)
            sqlite_conn.commit()
            cursor.close()

        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db(sqlite_conn)

    def connect_db(self):
        """
        Connect to the DB
        :return: None
        """
        try:
            self.connection = sqlite3.connect('pwdmngrdb.db')
            return self.connection
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))

    def disconnect_db(self):
        """
        Disconnect from the DB if connection exists
        :return: None
        """
        if self.connection:
            self.connection.close()

    def clear_db(self, table_name):
        """
        Clear all credential information.
        :return: bool: True if successful, False otherwise.
        """
        try:
            sqlite_conn = self.connect_db()
            cursor = sqlite_conn.cursor()
            delete_query = "DELETE FROM {}".format(table_name)
            cursor.execute(delete_query)
            sqlite_conn.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db(sqlite_conn)
