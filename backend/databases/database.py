import sqlite3

from abc import ABC
from backend.my_logger import logger


class Database(ABC):
    def __init__(self, table=None):
        self.table = table
        self.connection = None

    def create_table(self):
        pass

    def connect_db(self):
        """
        Connect to the DB
        Returns:
            None
        """
        try:
            self.connection = sqlite3.connect('pwdmngrdb.db')
            return self.connection
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
            return None

    def disconnect_db(self):
        """
        Disconnect from the DB if connection exists
        Returns:
             None
        """
        if self.connection:
            self.connection = self.connection.close()

    def clear_table(self):
        """
        Clear all credential information.
        Returns:
             True if successful, False otherwise.
        """
        try:
            sqlite_conn = self.connect_db()
            cursor = sqlite_conn.cursor()
            delete_query = "DELETE FROM {}".format(self.table)
            cursor.execute(delete_query)
            sqlite_conn.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def drop_table(self):
        """
        Drop the whole credential table.
        Returns:
             True if successful, False otherwise.
        """
        try:
            sqlite_conn = self.connect_db()
            cursor = sqlite_conn.cursor()
            drop_query = "DROP TABLE {}".format(self.table)
            cursor.execute(drop_query)
            sqlite_conn.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()
