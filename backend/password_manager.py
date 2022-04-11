from backend.crypto import compare_master_password_hash, create_master_key


class PasswordManager:
    """
    Class representing password manager.
    """
    def __init__(self, user_logged_in=False, master_key_db=None, credentials_db=None):
        self.user_logged_in = user_logged_in
        self.master_key_db = master_key_db
        self.credentials_db = credentials_db

    def sign_up(self):
        create_master_key()
        self.user_logged_in = True
        return True

    def check_user_exists(self, username):
        return True

    def login(self):
        username = input("Username: ")
        if self.check_user_exists(username):
            compare_master_password_hash()
        self.user_logged_in = True

    def logout(self):
        self.user_logged_in = False
