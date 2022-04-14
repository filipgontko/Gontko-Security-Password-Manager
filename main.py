from kivy.lang import Builder
from kivymd.app import MDApp

from backend.password_manager import PasswordManager


class PasswordManagerApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        return Builder.load_file('frontend/login.kv')

    def login(self, email, password):
        password_manager = PasswordManager()
        password_manager.login(email, password)

    def forgot_password(self):
        pass


PasswordManagerApp().run()
