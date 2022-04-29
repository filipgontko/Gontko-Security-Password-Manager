from kivy.lang import Builder
from kivy.properties import StringProperty
from kivymd.app import MDApp
from kivy.uix.screenmanager import Screen, ScreenManager
from kivymd.uix.button import MDRoundFlatButton, MDFillRoundFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import TwoLineListItem

from backend.crypto import check_password_strength


class Signup(Screen):
    def __init__(self, password_manager):
        super(Signup, self).__init__()
        self.password_manager = password_manager

    def signup(self, email, password):
        self.password_manager.sign_up(email, password)


class Login(Screen):
    def __init__(self, password_manager):
        super(Login, self).__init__()
        self.password_manager = password_manager

    def login(self, email, password):
        if self.password_manager.login(email, password):
            self.parent.current = "logged_in"

    def forgot_password(self):
        pass


class CustomTwoLineCredsListItem(TwoLineListItem):
    credential = StringProperty()


class LoggedIn(Screen):
    def __init__(self, password_manager):
        super(LoggedIn, self).__init__()
        self.password_manager = password_manager

    def on_enter(self):
        self.ids.search_field.text = "\r"
        self.ids.search_field.text = ""

    def on_leave(self):
        self.ids.search_field.text = ""
        self.ids.website.text = ""
        self.ids.username.text = ""
        self.ids.passwd.text = ""
        self.ids.generate_pwd.text = ""
        self.ids.strength_slider.value = 12
        self.ids.passwd.password = True
        self.ids.eye_icon.icon = "eye-off"

    def logout(self):
        self.password_manager.logout()

    def view_credentials(self, credential_id, website, username):
        self.parent.current = "creds_view"
        self.parent.transition.direction = "left"
        self.password_manager.credential_id = credential_id
        self.password_manager.credential_site = website
        self.password_manager.credential_username = username

    def add_credentials(self, site, username, password):
        self.password_manager.add_new_credentials(site, username, password)

    def generate_password(self, length=12):
        return self.password_manager.generate_password(length)

    def set_list_credentials(self, text="", search=True):
        def add_credential_item(cred_id, website, username):
            self.ids.rv.data.append(
                {
                    "viewclass": "CustomTwoLineCredsListItem",
                    "text": website,
                    "secondary_text": "username: {}".format(username),
                    "on_release": lambda: self.view_credentials(cred_id, website, username),
                    "callback": lambda x: x
                }
            )

        self.ids.rv.data = []
        try:
            for creds in self.password_manager.get_all_credentials():
                if search:
                    if text in creds[1]:
                        add_credential_item(creds[0], creds[1], creds[2])
                else:
                    add_credential_item(creds[0], creds[1], creds[2])
        except Exception as e:
            return None


class CredentialsView(Screen):
    def __init__(self, password_manager):
        super(CredentialsView, self).__init__()
        self.dialog = None
        self.password_manager = password_manager

    def on_enter(self):
        self.ids.website.text = self.get_site()
        self.ids.username.text = self.get_username()
        self.ids.passwd.text = self.get_password()
        self.show_password_strength()

    def on_leave(self):
        self.ids.generate_pwd.text = ""
        self.ids.strength_slider.value = 12
        self.ids.strength_meter.value = 0
        self.ids.strength_word.text = ""
        self.ids.passwd.password = True
        self.ids.eye_icon.icon = "eye-off"

    def get_site(self):
        return self.password_manager.credential_site

    def get_username(self):
        return self.password_manager.credential_username

    def get_password(self):
        try:
            return self.password_manager.get_password_from_db(self.password_manager.credential_id)
        except Exception as e:
            return ""

    def show_password_strength(self):
        strength_word = check_password_strength(self.ids.passwd.text)

        if strength_word == "Weak":
            self.ids.strength_meter.value = 25
            self.ids.strength_meter.color = [1, 0, 0, 1]
            self.ids.strength_word.text = strength_word

        if strength_word == "Moderate":
            self.ids.strength_meter.value = 50
            self.ids.strength_meter.color = [1, 0.9, 0, 1]
            self.ids.strength_word.text = strength_word

        if strength_word == "Strong":
            self.ids.strength_meter.value = 70
            self.ids.strength_meter.color = [0.5, 0.9, 0, 1]
            self.ids.strength_word.text = strength_word

        if strength_word == "Very Strong":
            self.ids.strength_meter.value = 100
            self.ids.strength_meter.color = [0, 1, 0, 1]
            self.ids.strength_word.text = strength_word

    def show_dialog(self, reason):
        if not self.dialog:
            self.set_dialog_context(reason)
        self.dialog.open()

    def set_dialog_context(self, reason):
        if reason == "delete":
            self.dialog = MDDialog(
                title="Delete credentials?",
                text="Are you sure you want to delete these credentials forever?",
                buttons=[
                    MDRoundFlatButton(text="CANCEL", on_release=self.close_dialog),
                    MDFillRoundFlatButton(text="DELETE", on_release=self.delete_credentials)
                ],
            )
        if reason == "save":
            self.dialog = MDDialog(
                title="Edit credentials?",
                text="Are you sure you want to overwrite current credentials?",
                buttons=[
                    MDRoundFlatButton(text="CANCEL", on_release=self.close_dialog),
                    MDFillRoundFlatButton(text="SAVE", on_release=self.save_credentials)
                ],
            )

    def close_dialog(self, obj):
        self.dialog.dismiss()
        self.dialog = None

    def save_credentials(self, obj):
        self.dialog.dismiss()
        self.dialog = None
        self.password_manager.edit_credentials(self.password_manager.credential_id,
                                               self.ids.website.text,
                                               self.ids.username.text,
                                               self.ids.passwd.text)

    def delete_credentials(self, obj):
        self.dialog.dismiss()
        self.dialog = None
        self.password_manager.remove_credentials(self.password_manager.credential_id)
        self.parent.current = "logged_in"
        self.parent.transition.direction = "right"

    def generate_password(self, length=12):
        return self.password_manager.generate_password(length)


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
        sm.add_widget(CredentialsView(self.password_manager))
        return sm

    def navigation_draw(self):
        """
        Navigation to be shown. Currently, doing nothing as it's used as logo only.
        """
        pass
