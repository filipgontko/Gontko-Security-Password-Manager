from kivy.lang import Builder
from kivy.properties import StringProperty
from kivymd.app import MDApp
from kivy.uix.screenmanager import Screen, ScreenManager
from kivymd.uix.list import ThreeLineListItem, TwoLineListItem
from kivymd.uix.relativelayout import MDRelativeLayout


class ClickableTextFieldRound(MDRelativeLayout):
    text = StringProperty()
    hint_text = StringProperty()


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


class CustomTwoLineCredsListItem(TwoLineListItem):
    credential = StringProperty()


class LoggedIn(Screen):
    def __init__(self, password_manager):
        super(LoggedIn, self).__init__()
        self.password_manager = password_manager

    def logout(self):
        self.password_manager.logout()

    def add_credentials(self, site, username, password):
        self.password_manager.add_new_credentials(site, username, password)

    def set_list_credentials(self, text="", search=False):
        def add_credential_item(website, username):
            self.ids.rv.data.append(
                {
                    "viewclass": "CustomTwoLineCredsListItem",
                    "text": website,
                    "secondary_text": "username: {}".format(username),
                    "on_release": lambda: self.password_manager.logout(),
                    "callback": lambda x: x
                }
            )
        # TODO: Open widget with credentials on release
        self.ids.rv.data = []
        for creds in self.password_manager.get_credentials():
            if search:
                if text in creds[0]:
                    add_credential_item(creds[0], creds[1])
            else:
                add_credential_item(creds[0], creds[1])

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
        """
        Navigation to be shown. Currently, doing nothing as it's used as logo only.a
        """
        pass
