from kivy.uix.screenmanager import Screen

from backend.crypto import generate_otp_url, generate_otp_qr_for_auth, chacha20_encrypt
from backend.my_logger import logger


class Signup(Screen):
    """
    Signup screen where user can sign up to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize Signup screen.
        Args:
            password_manager: Password manager object.
        """
        super(Signup, self).__init__()
        self.password_manager = password_manager

    def signup(self, username, password):
        """
        Sign up the user to the password manager.
        Args:
            username: Username of the user.
            password: Master password.
        """
        try:
            password = chacha20_encrypt(password)
            if self.password_manager.sign_up(username, password):
                self.setup_mfa()
        except Exception as e:
            logger.error("Exception occurred during signup. {}".format(e))

    def setup_mfa(self):
        """
        Generate OTP for user as MFA.
        """
        try:
            url = generate_otp_url(self.password_manager.username)
            generate_otp_qr_for_auth(url)
            self.parent.current = "mfa"
            self.parent.transition.direction = "left"
        except Exception as e:
            logger.error("Exception occurred during setting up MFA. {}".format(e))
