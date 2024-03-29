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
                with open("password_manager.env", "a") as env:
                    env.write("MFA=true\n")
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
                self.ids.otp.text = ""
        except Exception as e:
            logger.error("Exception occurred during comparison of OTP. {}".format(e))
