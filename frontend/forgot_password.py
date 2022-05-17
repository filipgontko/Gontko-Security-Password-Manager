from kivy.uix.screenmanager import Screen

from backend.crypto import chacha20_encrypt
from backend.my_logger import logger


class ForgotPassword(Screen):
    """
    Forgot password screen where user can reset master password to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize ForgotPassword screen.
        Args:
            password_manager: Password manager object.
        """
        super(ForgotPassword, self).__init__()
        self.password_manager = password_manager

    def reset(self, username, new_password, otp):
        """
        Reset password to the password manager.
        Args:
            username: Username of the user.
            new_password: New master password
            otp: OTP code from authenticator app.
        """
        try:
            password = chacha20_encrypt(new_password)
            if self.password_manager.reset_password(username, password, otp):
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
                self.ids.username.text = ""
                self.ids.otp.text = ""
                self.ids.master_password.text = ""
        except Exception as e:
            logger.error("Exception occurred during login(). {}".format(e))
