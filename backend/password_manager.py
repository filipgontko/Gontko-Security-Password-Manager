import re

from backend import crypto
from backend.credentials import Credentials
from backend.crypto import compare_master_password_hash, create_master_key
from backend.databases.master_key_database import MasterKeyDB
from backend.databases.credentials_database import CredentialsDB
from backend.my_logger import logger


def check_email(email):
    """
    Checks if e-mail is in valid format.
    Returns:
        True if successful, False otherwise.
    """
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(regex, email):
        logger.info("Valid e-mail address format.")
        return True
    else:
        logger.info("Invalid e-mail address format.")
        return False


class PasswordManager:
    """
    Class representing password manager.
    """
    def __init__(self, user_logged_in=False, email=None, credential_site=None, credential_username=None, credential_id=None):
        """
        Initialize password manager.
        Args:
            user_logged_in: True if user is logged in, False otherwise.
            email: E-mail address of the user.
        """
        self.user_logged_in = user_logged_in
        self.email = email
        self.master_db = MasterKeyDB()
        self.credentials_db = CredentialsDB()
        self.credential_site = credential_site
        self.credential_username = credential_username
        self.credential_id = credential_id

    def sign_up(self, email, password):
        """
        Sign up to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        if not check_email(email):
            return False
        try:
            self.email = email
            master_key_hash = create_master_key(password)
            self.master_db.insert_master_information(master_key_hash, self.email)
            self.user_logged_in = True
            logger.info("Successfully created user account with e-mail: %s.", self.email)
            return True
        except Exception as e:
            return False

    def check_user_exists(self):
        """
        Check if user is registered.
        Returns:
            True if successful, False otherwise.
        """
        return self.master_db.check_user_record_exists(self.email)

    def login(self, email, password):
        """
        Login to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        if not check_email(email):
            return False
        try:
            self.email = email
            logger.info("Initiating login...")
            if self.check_user_exists():
                stored_master_key_hash = self.master_db.get_master_key_hash(self.email)
                master_key_hash = compare_master_password_hash(password)
                if stored_master_key_hash == master_key_hash:
                    self.user_logged_in = True
                    logger.info("User with e-mail '{}' successfully logged in.".format(email))
                    return True
            logger.info("E-mail or password is incorrect.")
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
        # TODO: Show login screen

    def add_new_credentials(self, site, username, password):
        """
        Adds new credentials to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Adding new credentials into password_manager.")
                if site == "" or username == "" or password == "":
                    logger.info("Credentials contain empty string. Not adding to DB.")
                    return False
                credentials = Credentials(site, username, password)
                self.credentials_db.insert_credentials(credentials)
                logger.info("Credentials added successfully.")
                return True
        except Exception as e:
            logger.info("Credentials NOT added.")
            return False
        logger.error("User not logged in.")
        return False

    def edit_credentials(self, site, username, password, switcher):
        """
        Edit credentials in password manager.
        Args:
            site: Website
            username: Username
            password: Password
            switcher: String specifying what credentials to edit (site, username or password).

        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Editing credentials within password_manager.")
                if switcher == "password":
                    logger.info("Editing password...")
                    credentials = Credentials(site, username, password)
                    self.credentials_db.edit_credentials(credentials)
                elif switcher == "username":
                    logger.info("Editing username...")
                    credentials = Credentials(site, username, password)
                    # TODO: Edit username in db.
                elif switcher == "site":
                    logger.info("Editing website...")
                    credentials = Credentials(site, username, password)
                    # TODO: Edit site in db.
                else:
                    return False
                logger.info("Credentials edited successfully.")
                return True
        except Exception as e:
            logger.info("Credentials NOT edited.")
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
            logger.info("Credentials NOT deleted.")
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

    def get_credentials(self, site, username):
        """
        Get credentials to be viewed.
        Returns:
            List of credentials if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                logger.info("Getting specified credentials.")
                creds = Credentials(site, username)
                creds_list = self.credentials_db.view_credentials(creds)
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
                creds_list = self.credentials_db.get_password(credential_id)
                return creds_list
        except Exception as e:
            return None
        logger.error("User not logged in.")
        return None

    def generate_password(self, length):
        """
        Generate password on button click.
        Returns:
            Randomly generate password.
        """
        return crypto.generate_password(length)
