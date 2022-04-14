from kivy.lang import Builder
from kivymd.app import MDApp

from backend.password_manager import PasswordManager


class PasswordManagerApp(MDApp):
    def __init__(self, password_manager):
        super().__init__()
        self.password_manager = password_manager

    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        return Builder.load_file('frontend/login.kv')

    def login(self, email, password):
        self.password_manager.login(email, password)
        self.root.ids.email.text = ""
        self.root.ids.password.text = ""

    def forgot_password(self):
        pass


def run():
    password_manager = PasswordManager()
    if password_manager.master_db.is_empty():
        pass
    PasswordManagerApp(password_manager).run()


if __name__ == "__main__":
    run()
