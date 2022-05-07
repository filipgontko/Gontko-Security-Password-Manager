from kivy.uix.screenmanager import Screen

from backend.crypto import chacha20_encrypt
from backend.my_logger import logger


class Login(Screen):
    """
    Login screen where user can log in to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize Login screen.
        Args:
            password_manager: Password manager object.
        """
        super(Login, self).__init__()
        self.password_manager = password_manager

    def login(self, email, password):
        """
        Login to the password manager.
        Args:
            email: E-mail address of the user.
            password: Master password.

        """
        try:
            password = chacha20_encrypt(password)
            if self.password_manager.login(email, password):
                self.parent.current = "logged_in"
        except Exception as e:
            logger.error("Exception occurred during login(). {}".format(e))

    def forgot_password(self):
        """
        Takes the user to the forgot password screen.
        Returns:

        """
        pass
