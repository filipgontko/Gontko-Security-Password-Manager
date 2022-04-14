import sqlite3

from backend.databases.database import Database
from backend.my_logger import logger


class MasterKeyDB(Database):
    def __init__(self):
        super().__init__(table="master_table")
        self.create_table()

    def create_table(self):
        """
        Create table for storing master key hash and e-mail address it's connected with.
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS master_table (
                        master_key_hash TEXT,
                        email TEXT
                        );"""
            cursor.execute(create_table_query)
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()

    def insert_master_information(self, master_key_hash, email):
        """
        Insert information into the database.
        :param email: E-mail address of the account connected to the master key.
        :param master_key_hash: Master key hash.
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            insert_query = """INSERT INTO master_table(master_key_hash, email) 
                       VALUES (?, ?);"""
            cursor.execute(insert_query, (master_key_hash, email))
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while inserting - {}".format(error))
        finally:
            self.disconnect_db()

    def edit_master_information(self, email, master_key_hash_new):
        """
        Edit master key for an account. Hash (PBKDF2-SHA-256) of the new master key will be stored.
        :param email: E-mail of the account connected to the master key.
        :param master_key_hash_new: New master key hash.
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            update_query = """UPDATE master_table 
                            SET master_key_hash = ? 
                            WHERE email = ?"""
            cursor.execute(update_query, (master_key_hash_new, email))
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while updating password - {}".format(error))
        finally:
            self.disconnect_db()

    def get_master_key_hash(self, email):
        """
        Get the master key hash for the specified account.
        :param email: E-mail address of the account for which to retrieve the master key hash.
        :return: Hashed master key
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            get_mkey_query = """SELECT master_key_hash FROM master_table
                          WHERE email = '{}'""".format(email)
            cursor.execute(get_mkey_query)
            self.connection.commit()
            record = cursor.fetchone()[0]
            return record
        except sqlite3 as error:
            print("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()

    def check_user_record_exists(self, email):
        """
        Check if the specified user exists.
        :param email: E-mail address of the account which needs to be checked for existence.
        :return: True if user with the e-mail address exists, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            total_query = """SELECT EXISTS (SELECT 1 FROM master_table
                              WHERE email = '{}')""".format(email)
            cursor.execute(total_query)
            record = cursor.fetchone()[0]
            return record
        except sqlite3.Error as error:
            print("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()
