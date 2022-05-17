from kivy.uix.screenmanager import Screen

from backend.crypto import compare_totp
from backend.my_logger import logger


class MFA(Screen):
    """
    MFA screen where user will set up 2FA to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize MFA screen.
        Args:
            password_manager: Password manager object.
        """
        super(MFA, self).__init__()
        self.password_manager = password_manager

    def on_enter(self):
        self.ids.qr.source = "images/qr.png"

    def compare_otp(self, authenticator_otp):
        """
        Compare OTP for user.
        """
        try:
            if compare_totp(authenticator_otp):
                self.password_manager.mfa = True
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
        except Exception as e:
            logger.error("Exception occurred during comparison of OTP. {}".format(e))
