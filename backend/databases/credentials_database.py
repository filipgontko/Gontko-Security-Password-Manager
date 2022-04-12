import sqlite3

from backend.databases.database import Database
from backend.my_logger import logger
from backend.crypto import encrypt_message


class CredentialsDB(Database):
    def __init__(self):
        super().__init__(table="credentials_table")

    def create_table(self):
        """
        Create table for storing username, password and site.
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS credentials_table (
                            site TEXT,
                            username TEXT,
                            password TEXT
                            );"""
            cursor.execute(create_table_query)
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()

    def insert_credentials(self, credentials):
        """
        Insert credentials into the database.
        :param credentials: Credentials object for which to store username and password
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            encrypted_password = encrypt_message(credentials.password)
            insert_query = """INSERT INTO credentials_table(site, username, password) 
                           VALUES ('{}', '{}', {});""".format(credentials.site, credentials.username, encrypted_password)
            cursor.execute(insert_query)
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while inserting - {}".format(error))
        finally:
            self.disconnect_db()

    # TODO: Password history should be accessible at least for the last 3 passwords per site.
    # TODO: Edit all credentials should be poosible.
    def edit_password(self, credentials):
        """
        Edit the credential for a specific site. Change either credential is possible.
        :param credentials: Credentials object for which to store username and password
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            update_query = """UPDATE credentials_table 
                            SET password = '{}' 
                            WHERE site = '{}' AND username = '{}'""".format(credentials.password, credentials.site,
                                                                            credentials.username)
            cursor.execute(update_query)
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while updating password - {}".format(error))
        finally:
            self.disconnect_db()

    def get_password(self, credentials):
        """
        Get the password for a specific site.
        :param credentials: Credentials object for which to retrieve the password.
        :return: Encrypted password.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            total_query = """SELECT password FROM credentials_table
                          WHERE site = '{}' AND username = '{}'""".format(credentials.site, credentials.username)
            cursor.execute(total_query)
            record = cursor.fetchone()[0]
            return record
        except sqlite3.Error as error:
            print("Error while connecting to the DB - {}".format(error))
        finally:
            self.disconnect_db()

    def delete_credentials(self, credentials):
        """
        Delete credentials from the database.
        :param credentials: Credentials object to be removed.
        :return: bool: True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            delete_query = """DELETE FROM credentials_table 
                            WHERE site = '{}' AND username = '{}'""".format(credentials.site, credentials.username)
            cursor.execute(delete_query)
            self.connection.commit()
            cursor.close()
        except sqlite3.Error as error:
            logger.error("Error while deleting - {}".format(error))
        finally:
            self.disconnect_db()
