import sqlite3

from backend.databases.database import Database
from backend.my_logger import logger


class MasterKeyDB(Database):
    def __init__(self):
        super().__init__(table="master_table")
        self.create_table()

    def create_table(self):
        """
        Create table for storing master key hash and username it's connected with.
        Returns:
             True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS master_table (
                        master_key_hash TEXT,
                        username TEXT
                        );"""
            cursor.execute(create_table_query)
            self.connection.commit()
            cursor.close()
            logger.info("Master table created successfully.")
            return True
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def insert_master_information(self, master_key_hash, username):
        """
        Insert information into the database.
        Args:
            master_key_hash: Master key hash.
            username: Username of the account connected to the master key.

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            insert_query = """INSERT INTO master_table(master_key_hash, username) 
                       VALUES (?, ?);"""
            cursor.execute(insert_query, (master_key_hash, username))
            self.connection.commit()
            cursor.close()
            logger.info("Successfully inserted information into master table.")
            return True
        except sqlite3.Error as error:
            logger.error("Error while inserting - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def edit_master_information(self, username, master_key_hash_new):
        """
        Edit master key for an account. Hash (PBKDF2-SHA-256) of the new master key will be stored.
        Args:
            username: Username of the account connected to the master key.
            master_key_hash_new: New master key hash.

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            update_query = """UPDATE master_table 
                            SET master_key_hash = ? 
                            WHERE username = ?"""
            cursor.execute(update_query, (master_key_hash_new, username))
            self.connection.commit()
            cursor.close()
            logger.info("Successfully updated master key information within master table.")
            return True
        except sqlite3.Error as error:
            logger.error("Error while updating password - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def get_master_key_hash(self, username):
        """
        Get the master key hash for the specified account.
        Args:
            username: Username of the account for which to retrieve the master key hash.

        Returns:
            Hashed master key
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            get_mkey_query = """SELECT master_key_hash FROM master_table
                          WHERE username = '{}'""".format(username)
            cursor.execute(get_mkey_query)
            self.connection.commit()
            record = cursor.fetchone()[0]
            logger.info("Fetching master key hash...")
            return record
        except sqlite3 as error:
            print("Error while connecting to the DB - {}".format(error))
            return None
        finally:
            self.disconnect_db()

    def check_user_record_exists(self, username):
        """
        Check if the specified user exists.
        Args:
            username: Username of the account which needs to be checked for existence.

        Returns:
            True if user with the username exists, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            total_query = """SELECT EXISTS (SELECT 1 FROM master_table
                              WHERE username = '{}')""".format(username)
            cursor.execute(total_query)
            record = cursor.fetchone()[0]
            logger.info("Checking if user with the username: {} exists.".format(username))
            return record
        except sqlite3.Error as error:
            print("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def is_empty(self):
        """
        Check if the database is empty.
        Returns:
            True if empty, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            empty_query = """SELECT COUNT(*) FROM master_table"""
            cursor.execute(empty_query)
            record = cursor.fetchall()
            logger.info("Checking if master table is empty.")
            return record[0][0] == 0
        except sqlite3.Error as error:
            print("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()
