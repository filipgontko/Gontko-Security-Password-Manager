from kivy.lang import Builder
from kivy.properties import StringProperty
from kivymd.app import MDApp
from kivy.uix.screenmanager import ScreenManager

from kivymd.uix.list import TwoLineListItem
from frontend.credentials_view import CredentialsView
from frontend.logged_in import LoggedIn
from frontend.login import Login
from frontend.signup import Signup


class CustomTwoLineCredsListItem(TwoLineListItem):
    credential = StringProperty()


# This needs to be global in order for the screen manager to lead the screens.
Builder.load_file("frontend/password_manager.kv")


class PasswordManagerApp(MDApp):
    """
    Password manager Kivy app.
    """
    def __init__(self, password_manager):
        """
        Initialize PasswordManagerApp MDApp.
        Args:
            password_manager: Password manager object.
        """
        super().__init__()
        self.password_manager = password_manager

    def build(self):
        """
        Add screens to the ScreenManager and set up the theme style.
        Returns:
            Screen manager.
        """
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Amber"
        self.theme_cls.accent_palette = "Orange"
        sm = ScreenManager()
        if self.password_manager.master_db.is_empty():
            sm.add_widget(Signup(self.password_manager))
        sm.add_widget(Login(self.password_manager))
        sm.add_widget(LoggedIn(self.password_manager))
        sm.add_widget(CredentialsView(self.password_manager))
        return sm

    def navigation_draw(self):
        """
        Navigation to be shown. Currently, doing nothing as it's used as logo only.
        """
        pass
