from kivy.uix.screenmanager import Screen

from backend.crypto import compare_totp
from backend.my_logger import logger


class MFA(Screen):
    """
    Signup screen where user can sign up to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize Signup screen.
        Args:
            password_manager: Password manager object.
        """
        super(MFA, self).__init__()
        self.password_manager = password_manager

    def compare_otp(self, google_otp):
        """
        Compare OTP for user.
        """
        try:
            if compare_totp(google_otp):
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
        except Exception as e:
            logger.error("Exception occurred during signup. {}".format(e))
