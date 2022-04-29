from kivy.uix.screenmanager import Screen


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

    def signup(self, email, password):
        """
        Sign up the user to the password manager.
        Args:
            email: E-mail address of the user.
            password: Master password.
        """
        self.password_manager.sign_up(email, password)
