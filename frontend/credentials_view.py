from kivy.uix.screenmanager import Screen
from kivymd.uix.button import MDRoundFlatButton, MDFillRoundFlatButton
from kivymd.uix.dialog import MDDialog

from backend.crypto import check_if_pwned, check_password_strength
from backend.password_manager import generate_password


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
        if check_if_pwned(self.ids.passwd.text):
            self.dialog = MDDialog(text="OOOPS! Your password has been pwned! Change it now")
            self.dialog.open()
            self.dialog = ""

    def on_leave(self):
        self.ids.generate_pwd.text = ""
        self.ids.strength_slider.value = 12
        self.ids.strength_meter.value = 0
        self.ids.strength_word.text = ""
        self.ids.passwd.password = True
        self.ids.eye_icon.icon = "eye-off"
        self.ids.pwned.text = ""

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

        if check_if_pwned(self.ids.passwd.text):
            self.ids.pwned.text = "Your password has been pwned!"
            strength_word = "Weak"
        else:
            self.ids.pwned.text = "Your password has not been pwned!"

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
        self.dialog = ""

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
        return generate_password(length)
