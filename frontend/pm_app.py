from kivy.lang import Builder
from kivy.properties import StringProperty
from kivymd.app import MDApp
from kivy.uix.screenmanager import Screen, ScreenManager
from kivymd.icon_definitions import md_icons
from kivymd.uix.list import OneLineListItem


class Login(Screen):
    def __init__(self, password_manager):
        super(Login, self).__init__()
        self.password_manager = password_manager

    def login(self, email, password):
        if self.password_manager.login(email, password):
            self.parent.current = "logged_in"

    def forgot_password(self):
        pass


class Signup(Screen):
    def __init__(self, password_manager):
        super(Signup, self).__init__()
        self.password_manager = password_manager

    def signup(self, email, password):
        self.password_manager.sign_up(email, password)


class CustomOneLineCredsListItem(OneLineListItem):
    credential = StringProperty()


class LoggedIn(Screen):
    def __init__(self, password_manager):
        super(LoggedIn, self).__init__()
        self.password_manager = password_manager

    def logout(self):
        self.password_manager.logout()

    def set_list_credentials(self, text="", search=False):
        def add_credential_item(site_name):
            self.ids.rv.data.append(
                {
                    "viewclass": "CustomOneLineCredsListItem",
                    "text": site_name,
                    "callback": lambda x: x,
                }
            )
        self.ids.rv.data = []
        # TODO: Change to search the list of credentials
        for site_name in self.password_manager.get_credentials():
            if search:
                if text in site_name:
                    add_credential_item(site_name)
            else:
                add_credential_item(site_name)

    data = {
        'Add credentials': 'plus-circle-outline',
        'Edit credentials': 'pencil-outline',
        'Generate password': 'key-outline',
    }


# This needs to be global in order for the screen manager to lead the screens.
Builder.load_file("frontend/password_manager.kv")


class PasswordManagerApp(MDApp):
    def __init__(self, password_manager):
        super().__init__()
        self.password_manager = password_manager

    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Amber"
        self.theme_cls.accent_palette = "Orange"
        sm = ScreenManager()
        if self.password_manager.master_db.is_empty():
            sm.add_widget(Signup(self.password_manager))
        sm.add_widget(Login(self.password_manager))
        sm.add_widget(LoggedIn(self.password_manager))
        return sm

    def navigation_draw(self):
        pass
