from kivy.uix.screenmanager import Screen

from backend.my_logger import logger


class LoginPwdless(Screen):
    """
    Login screen where user can log in to the password manager without master password.
    """
    def __init__(self, password_manager):
        """
        Initialize Login screen.
        Args:
            password_manager: Password manager object.
        """
        super(LoginPwdless, self).__init__()
        self.password_manager = password_manager

    def login(self, username, code):
        """
        Login to the password manager.
        Args:
            username: Username of the user.
            code: Authenticator code.

        """
        try:
            if self.password_manager.password_less_login(username, code):
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
                self.ids.username.text = ""
                self.ids.otp.text = ""
        except Exception as e:
            logger.error("Exception occurred during login(). {}".format(e))
