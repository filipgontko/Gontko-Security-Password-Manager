import sqlite3

from backend.databases.database import Database
from backend.my_logger import logger
from backend.crypto import encrypt_message, decrypt_message


class CredentialsDB(Database):
    def __init__(self):
        super().__init__(table="credentials_table")
        self.create_table()

    def create_table(self):
        """
        Create table for storing username, password and site.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            create_table_query = """CREATE TABLE IF NOT EXISTS credentials_table (
                            id INTEGER PRIMARY KEY,
                            site TEXT,
                            username TEXT,
                            password TEXT
                            );"""
            cursor.execute(create_table_query)
            self.connection.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while connecting to the DB - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def insert_credentials(self, credentials):
        """
        Insert credentials into the database.
        Args:
            credentials: credentials object for which to store username and password

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            encrypted_password = encrypt_message(credentials.password)
            insert_query = """INSERT INTO credentials_table(site, username, password) 
                           VALUES (?, ?, ?);"""
            cursor.execute(insert_query, (credentials.site, credentials.username, encrypted_password))
            self.connection.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while inserting - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    # TODO: Password history should be accessible at least for the last 3 passwords per site.
    def edit_credentials(self, credential_id, credentials):
        """
        Edit the credential for a specific site. Change either credential is possible.
        Args:
            credential_id: Credential ID for which to edit credentials.
            credentials: Credentials object for which to store username and password

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            encrypted_password = encrypt_message(credentials.password)
            update_query = """UPDATE credentials_table 
                            SET site = ?, username = ?, password = ?
                            WHERE id = ?;"""
            cursor.execute(update_query, (credentials.site, credentials.username, encrypted_password, credential_id))
            self.connection.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while updating password - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def get_password(self, credential_id):
        """
        Get the password for a specific site.
        Args:
            credential_id: Credential ID for which to retrieve the password.

        Returns:
            Encrypted password.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            get_pass_query = """SELECT password FROM credentials_table WHERE id = {}""".format(credential_id)
            cursor.execute(get_pass_query)
            self.connection.commit()
            record = cursor.fetchone()[0]
            decrypted_password = decrypt_message(record)
            return decrypted_password
        except sqlite3.Error as error:
            print("Error while connecting to the DB - {}".format(error))
            return None
        finally:
            self.disconnect_db()

    def delete_credentials(self, credential_id):
        """
        Delete credentials from the database.
        Args:
            credential_id: Credential ID of a credential to be removed.

        Returns:
            True if successful, False otherwise.
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            delete_query = """DELETE FROM credentials_table WHERE id = {}""".format(credential_id)
            cursor.execute(delete_query)
            self.connection.commit()
            cursor.close()
            return True
        except sqlite3.Error as error:
            logger.error("Error while deleting - {}".format(error))
            return False
        finally:
            self.disconnect_db()

    def view_all_credentials(self):
        """
        View stored sites and usernames in the database
        Returns:
            List of credentials tuples (site, username)
        """
        try:
            self.connect_db()
            cursor = self.connection.cursor()
            view_query = "SELECT id, site, username FROM credentials_table"
            cursor.execute(view_query)
            self.connection.commit()
            record = cursor.fetchall()
            return record
        except sqlite3.Error as error:
            logger.error("Error while getting all credentials - {}".format(error))
            return None
        finally:
            self.disconnect_db()
