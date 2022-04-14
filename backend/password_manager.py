from backend.credentials import Credentials
from backend.crypto import compare_master_password_hash, create_master_key
from backend.databases.master_key_database import MasterKeyDB
from backend.databases.credentials_database import CredentialsDB
from backend.my_logger import logger


def prepare_credentials(password_change=False):
    """
    Prepare credentials that will be either created, updated, or deleted.
    Returns:
        Credentials object
    """
    site = input("Website: ")
    username = input("Username: ")
    password = None
    if password_change:
        password = input("New password: ")
    credentials = Credentials(site, username, password)
    password = "*********"  # Overwrite password so it doesn't stay in memory.
    return credentials


class PasswordManager:
    """
    Class representing password manager.
    """
    def __init__(self, user_logged_in=False, email=None):
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

    def sign_up(self):
        """
        Sign up to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.email = input("E-mail: ")
            master_key_hash = create_master_key()
            self.master_db.insert_master_information(master_key_hash, self.email)
            self.user_logged_in = True
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

    def login(self):
        """
        Login to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.email = input("E-mail: ")
            if self.check_user_exists():
                stored_master_key_hash = self.master_db.get_master_key_hash(self.email)
                master_key_hash = compare_master_password_hash()
                if stored_master_key_hash == master_key_hash:
                    self.user_logged_in = True
            return self.user_logged_in
        except Exception as e:
            return False

    def check_user_logged_in(self):
        """
        Checks if user is logged into the password manager.
        Returns:
            True if successful, False otherwise.
        """
        return self.user_logged_in

    def logout(self):
        """
        Logout from password manager.
        Returns:
            None
        """
        self.user_logged_in = False
        # TODO: Show login screen

    def add_new_credentials(self):
        """
        Adds new credentials to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                credentials = prepare_credentials(True)
                self.credentials_db.insert_credentials(credentials)
                return True
        except Exception as e:
            return False
        logger.error("User not logged in.")
        return False

    def edit_credentials(self, switcher):
        """
        Edit credentials in password manager.
        Args:
            switcher: String specifying what credentials to edit (site, username or password).

        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                if switcher == "password":
                    credentials = prepare_credentials(True)
                    self.credentials_db.edit_password(credentials)
                elif switcher == "username":
                    credentials = prepare_credentials()
                    # TODO: Edit username in db.
                elif switcher == "site":
                    credentials = prepare_credentials()
                    # TODO: Edit site in db.
                else:
                    return False
                return True
        except Exception as e:
            return False
        logger.error("User not logged in.")
        return False

    def remove_credentials(self):
        """
        Remove credentials from password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                credentials = prepare_credentials()
                self.credentials_db.delete_credentials(credentials)
                return True
        except Exception as e:
            return False
        logger.error("User not logged in.")
        return False

    def get_credentials(self):
        """
        Get credentials to be viewed.
        Returns:
            List of credentials if successful, False otherwise.
        """
        try:
            if self.check_user_logged_in():
                credentials = prepare_credentials()
                creds_list = self.credentials_db.view_credentials(credentials)
                return creds_list
        except Exception as e:
            return None
        logger.error("User not logged in.")
        return None
