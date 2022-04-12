import sqlite3

from abc import ABC
from backend.my_logger import logger


class Database(ABC):
    def __init__(self, connection=None, table=None):
        self.connection = connection
        self.table = table

    def create_table(self):
        pass

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
            self.connection = self.connection.close()

    def clear_table(self):
        """
        Clear all credential information.
        :return: bool: True if successful, False otherwise.
        """
        try:
            sqlite_conn = self.connect_db()
            cursor = sqlite_conn.cursor()
            delete_query = "DELETE FROM {}".format(self.table)
            cursor.execute(delete_query)
            sqlite_conn.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()
