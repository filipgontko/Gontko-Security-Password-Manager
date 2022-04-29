from kivy.uix.screenmanager import Screen


class Login(Screen):
    """
    Login screen where user can login to the password manager.
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
            password: Password.

        """
        if self.password_manager.login(email, password):
            self.parent.current = "logged_in"

    def forgot_password(self):
        """
        Takes the user to the forgot password screen.
        Returns:

        """
        pass
