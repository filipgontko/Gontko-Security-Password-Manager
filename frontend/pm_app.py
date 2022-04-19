from kivy.lang import Builder
from kivymd.app import MDApp
from kivy.uix.screenmanager import Screen, ScreenManager

from backend.password_manager import PasswordManager


class Login(Screen):
    def __init__(self, password_manager):
        super(Login, self).__init__()
        self.password_manager = password_manager

    def login(self, email, password):
        if self.password_manager.login(email, password):
            self.parent.current = "third"


class Signup(Screen):
    def __init__(self, password_manager):
        super(Signup, self).__init__()
        self.password_manager = password_manager

    def signup(self, email, password):
        self.password_manager.sign_up(email, password)


class Third(Screen):
    pass


class WindowManager(ScreenManager):
    pass


Builder.load_file("password_manager.kv")


class PasswordManagerApp(MDApp):
    def __init__(self, password_manager):
        super().__init__()
        self.password_manager = password_manager

    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        sm = ScreenManager()
        if self.password_manager.master_db.is_empty():
            sm.add_widget(Signup(self.password_manager))
        sm.add_widget(Login(self.password_manager))
        sm.add_widget(Third(name="third"))
        return sm

    def forgot_password(self):
        pass


def run():
    password_manager = PasswordManager()
    PasswordManagerApp(password_manager).run()


if __name__ == "__main__":
    run()
