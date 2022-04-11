from backend.crypto import compare_master_password_hash, create_master_key
from backend.databases.master_key_database import check_user_record_exists, create_table, insert_master_information


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

    def sign_up(self):
        """
        Sign up to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            create_table()
            master_key_hash = create_master_key()
            self.email = input("E-mail: ")
            insert_master_information(master_key_hash, self.email)
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
        return check_user_record_exists(self.email)

    def login(self):
        """
        Login to the password manager.
        Returns:
            True if successful, False otherwise.
        """
        try:
            self.email = input("E-mail: ")
            if self.check_user_exists():
                compare_master_password_hash()
            self.user_logged_in = True
            return True
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
