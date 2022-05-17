import re

from backend import crypto
from backend.credentials import Credentials
from backend.crypto import recreate_master_password_hash, create_master_key, encrypt_message, decrypt_message, \
    generate_chacha20_key, chacha20_encrypt, chacha20_decrypt
from backend.databases.master_key_database import MasterKeyDB
from backend.databases.credentials_database import CredentialsDB
from backend.my_logger import logger


def generate_password(length):
    """
    Generate password on button click.
    Returns:
        Randomly generate password.
    """
    return crypto.generate_password(length)


class PasswordManager:
    """
    Class representing password manager.
    """
    def __init__(self):
        """
        Initialize password manager.
        """
        self.user_logged_in = False
        self.username = None
        self.master_db = MasterKeyDB()
        self.master_password = None
        self.credentials_db = CredentialsDB()
        self.credential_name = None
        self.credential_site = None
        self.credential_username = None
        self.credential_id = None
        generate_chacha20_key()

    def sign_up(self, username, password):
        """
        Sign up to the password manager.
        Args:
            username: Username of the user.
            password: Master password.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.username = username
            self.master_password = password
            master_key_hash = create_master_key(password)
            self.master_db.insert_master_information(master_key_hash, self.username)
            self.user_logged_in = True
            logger.info("Successfully created user account with username: {}.".format(self.username))
            return True
        except Exception as e:
            logger.error("User account creation with username: {} failed.".format(self.username))
            return False

    def check_user_exists(self):
        """
        Check if user is registered.
        Returns:
            True if successful, False otherwise.
        """
        return self.master_db.check_user_record_exists(self.username)

    def login(self, username, password):
        """
        Login to the password manager.
        Args:
            username: Username of the user.
            password: Master password.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.username = username
            logger.info("Initiating login...")
            if self.check_user_exists():
                stored_master_key_hash = self.master_db.get_master_key_hash(self.username)
                master_key_hash = recreate_master_password_hash(password)
                if stored_master_key_hash == master_key_hash:
                    self.master_password = password
                    self.user_logged_in = True
                    logger.info("User with username '{}' successfully logged in.".format(username))
                    return True
                logger.error("User with username '{}' failed to log in.".format(username))
            logger.error("Username or password is incorrect.")
            return False
        except Exception as e:
            return False

    def reset_password(self, username, password, otp):
        """
        Reset master password to the password manager.
        Args:
            username: Username of the user.
            password: Master password.
            otp: OTP code from authenticator app
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.username = username
            logger.info("Initiating password reset...")
            if self.check_user_exists():
                stored_master_key_hash = self.master_db.get_master_key_hash(self.username)
                master_key_hash = recreate_master_password_hash(password)
                if stored_master_key_hash == master_key_hash:
                    self.master_password = password
                    self.user_logged_in = True
                    logger.info("User with username '{}' successfully logged in.".format(username))
                    return True
                logger.error("User with username '{}' failed to log in.".format(username))
            logger.error("Username or password is incorrect.")
            return False
        except Exception as e:
            return False

    def check_user_logged_in(self):
        """
        Checks if user is logged into the password manager.
        Returns:
            True if successful, False otherwise.
        """
        logger.info("Checking if user is logged in.")
        return self.user_logged_in

    def logout(self):
        """
        Logout from password manager.
        Returns:
            None
        """
        logger.info("Logging out...")
        self.user_logged_in = False

    def add_new_credentials(self, name, site, username, password):
        """
        Adds new credentials to the password manager.
        Args:
            name: Credential name.
            site: Website
            username: Username
            password: Password
        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Adding new credentials into password_manager.")
                if name == "" or username == "" or password == "":
                    logger.error("Credentials contain empty string. Not adding to DB.")
                    return False
                encrypted_password = encrypt_message(chacha20_decrypt(password), self.master_password)
                credentials = Credentials(name, site, username, encrypted_password)
                self.credentials_db.insert_credentials(credentials)
                logger.info("Credentials added successfully.")
                return True
        except Exception as e:
            logger.error("Credentials NOT added.")
            return False
        logger.error("User not logged in.")
        return False

    def edit_credentials(self, cred_id, name, site, username, password):
        """
        Edit credentials in password manager.
        Args:
            cred_id: Credential ID
            name: Credential name.
            site: Website
            username: Username
            password: Password

        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Editing credentials within password_manager.")
                encrypted_password = encrypt_message(chacha20_decrypt(password), self.master_password)
                credentials = Credentials(name, site, username, encrypted_password)
                self.credentials_db.edit_credentials(cred_id, credentials)
                logger.info("Credentials edited successfully.")
                return True
        except Exception as e:
            logger.error("Credentials NOT edited.")
            return False
        logger.error("User not logged in.")
        return False

    def remove_credentials(self, credential_id):
        """
        Remove credentials from password manager.
        Args:
            credential_id: ID of the credential to be removed.
        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Removing credentials from password_manager.")
                self.credentials_db.delete_credentials(credential_id)
                logger.info("Credentials deleted successfully.")
                return True
        except Exception as e:
            logger.error("Credentials NOT deleted.")
            return False
        logger.error("User not logged in.")
        return False

    def get_all_credentials(self):
        """
        Get credentials to be viewed.
        Returns:
            List of credentials if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Getting list of all credentials.")
                creds_list = self.credentials_db.view_all_credentials()
                return creds_list
        except Exception as e:
            return None
        logger.error("User not logged in.")
        return None

    def get_password_from_db(self, credential_id):
        """
        Get credentials to be viewed.
        Returns:
            List of credentials if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Getting password for specified credentials.")
                password = self.credentials_db.get_password(credential_id)
                decrypted_password = decrypt_message(password, self.master_password)
                return chacha20_encrypt(decrypted_password)
        except Exception as e:
            logger.error("Getting password for specified credentials failed.")
            return None
        logger.error("User not logged in.")
        return None
