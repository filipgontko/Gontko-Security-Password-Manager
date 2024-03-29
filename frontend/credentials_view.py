from kivy.uix.screenmanager import Screen
from kivymd.uix.button import MDRoundFlatButton, MDFillRoundFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.snackbar import Snackbar

from backend.crypto import check_if_pwned, check_password_strength, chacha20_decrypt, chacha20_encrypt
from backend.my_logger import logger
from backend.password_manager import generate_password


class CredentialsView(Screen):
    """
    Screen showing credentials information.
    On this screen it is possible to delete and edit credentials, and generate passwords.
    Additionally, it shows the password strength and notifies the user if the password has been pwned.
    """

    def __init__(self, password_manager):
        """
        Initialize CredentialsView screen.
        Args:
            password_manager: Password manager object.
        """
        super(CredentialsView, self).__init__()
        self.dialog = None
        self.password_manager = password_manager

    def on_enter(self):
        """
        Initialize text fields, strength meter and check if pawned, when entering the view.
        """
        try:
            self.ids.cred_name.text = self.get_cred_name()
            self.ids.website.text = self.get_site()
            self.ids.username.text = self.get_username()
            self.ids.passwd.text = chacha20_decrypt(self.get_password())
            self.show_password_strength()
            self.is_pwned_message()
        except Exception as e:
            logger.error("Exception occurred during on_enter(). {}".format(e))

    def on_leave(self):
        """
        Clear the text fields, strength meter, check if pawned and set password field to show masked password
        when leaving the view.
        """
        try:
            self.ids.cred_name.text = ""
            self.ids.website.text = ""
            self.ids.username.text = ""
            self.ids.passwd.text = ""
            self.ids.generate_pwd.text = ""
            self.ids.strength_slider.value = 12
            self.ids.strength_meter.value = 0
            self.ids.strength_word.text = ""
            self.ids.passwd.password = True
            self.ids.eye_icon.icon = "eye-off"
            self.ids.pwned.text = ""
            self.ids.copy_pass.text = "COPY"
        except Exception as e:
            logger.error("Exception occurred during on_leave(). {}".format(e))

    def get_cred_name(self):
        """
        Get credential name.
        Returns:
            Username string if successful, empty string otherwise.
        """
        try:
            return self.password_manager.credential_name
        except Exception as e:
            logger.error("Get username failed. {}".format(e))
            return ""

    def get_site(self):
        """
        Get the site. If the site doesn't contain 'https://' or 'http://' prefix, it will be added.
        Returns:
            Site string if successful, empty string otherwise.
        """
        try:
            site = self.password_manager.credential_site
            prefix = "https://"
            not_secure_prefix = "http://"
            if (prefix in site) or (not_secure_prefix in site):
                return site
            else:
                return prefix + site
        except Exception as e:
            logger.error("Get site failed. {}".format(e))
            return ""

    def get_username(self):
        """
        Get username.
        Returns:
            Username string if successful, empty string otherwise.
        """
        try:
            return self.password_manager.credential_username
        except Exception as e:
            logger.error("Get username failed. {}".format(e))
            return ""

    def get_password(self):
        """
        Get password from DB.
        Returns:
            Decrypted password string if successful, empty string otherwise.
        """
        try:
            return self.password_manager.get_password_from_db(self.password_manager.credential_id)
        except Exception:
            return ""

    def is_pwned_message(self):
        """
        Shows a dialog with a message that the password had been pwned!
        """
        try:
            if check_if_pwned(chacha20_encrypt(self.ids.passwd.text)):
                self.dialog = MDDialog(text="OOOPS! Your password has been pwned! Change it now")
                self.dialog.open()
                self.dialog = None
        except Exception as e:
            logger.error("Exception occurred during showing pwned dialog. {}".format(e))

    def show_password_strength(self):
        """
        Show password strength.
        """
        try:
            strength_word = check_password_strength(self.ids.passwd.text)

            if check_if_pwned(chacha20_encrypt(self.ids.passwd.text)):
                self.ids.pwned.text = "Your password has been pwned!"
                strength_word = "Weak"
            else:
                self.ids.pwned.text = "Your password has not been pwned!"

            self.set_strength_values(strength_word)
        except Exception as e:
            logger.error("Exception occurred in show_password_strength(). {}".format(e))

    def set_strength_values(self, strength_word):
        """
        Set the values for the strength meter to be shown.
        Args:
            strength_word: Verbal description of the password strength.
        """
        try:
            if strength_word == "Weak":
                self.prepare_strength_values(25, [1, 0, 0, 1], strength_word)

            if strength_word == "Moderate":
                self.prepare_strength_values(50, [1, 0.9, 0, 1], strength_word)

            if strength_word == "Strong":
                self.prepare_strength_values(70, [0.5, 0.9, 0, 1], strength_word)

            if strength_word == "Very Strong":
                self.prepare_strength_values(100, [0, 1, 0, 1], strength_word)
        except Exception as e:
            logger.error("Exception occurred while setting strength values. {}".format(e))

    def prepare_strength_values(self, value, color, word):
        """
        Prepare the value, color and word description of the password strength.
        Args:
            value: Value on the strength meter.
            color: Color of the strength.
            word: Verbal description of the password strength.

        """
        try:
            self.ids.strength_meter.value = value
            self.ids.strength_meter.color = color
            self.ids.strength_word.text = word
        except Exception as e:
            logger.error("Exception occurred while preparing strength value, color and word. {}".format(e))

    def show_dialog(self, reason):
        """
        Show dialog on screen.
        Args:
            reason: Delete or Save.
        """
        try:
            self.dialog = None
            if not self.dialog:
                self.set_dialog_context(reason)
            self.dialog.open()
        except Exception as e:
            logger.error("Exception occurred during show_dialog(). {}".format(e))

    def set_dialog_context(self, reason):
        """
        Set up the dialog context to be shown.
        Args:
            reason: Delete or Save.
        """
        try:
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
        except Exception as e:
            logger.error("Exception occurred while setting dialog context. {}".format(e))

    def close_dialog(self, obj):
        """
        Close the dialog and set it to None.
        Args:
            obj: Dialog object.
        """
        try:
            self.dialog.dismiss()
            self.dialog = None
        except Exception as e:
            logger.error("Exception occurred while closing dialog. {}".format(e))

    def save_credentials(self, obj):
        """
        Save credentials to the database.
        Args:
            obj: Dialog object.
        """
        try:
            self.dialog.dismiss()
            self.dialog = None
            self.password_manager.edit_credentials(self.password_manager.credential_id,
                                                   self.ids.cred_name.text,
                                                   self.ids.website.text,
                                                   self.ids.username.text,
                                                   chacha20_encrypt(self.ids.passwd.text))
        except Exception as e:
            logger.error("Exception occurred while saving credentials. {}".format(e))

    def delete_credentials(self, obj):
        """
        Delete credentials from the database.
        Args:
            obj: Dialog object.
        """
        try:
            self.dialog.dismiss()
            self.dialog = None
            self.password_manager.remove_credentials(self.password_manager.credential_id)
            self.parent.current = "logged_in"
            self.parent.transition.direction = "right"
        except Exception as e:
            logger.error("Exception occurred while deleting credentials. {}".format(e))

    def generate_password(self, length=12):
        """
        Generate a strong password.
        Args:
            length: Length of the password (minimum length is 12 characters).

        Returns:
            Password string.
        """
        try:
            return generate_password(length)
        except Exception as e:
            logger.error("Exception occurred during password generation. {}".format(e))
            return ""

    def show_snackbar(self):
        """
        Shows a snackbar with a message on the bottom of the screen.
        """
        snackbar = Snackbar(
            text="Generated password has been copied to clipboard!",
            snackbar_x="10dp",
            snackbar_y="10dp",
            height=30,
            duration=1
        )
        snackbar.size_hint_x = (self.ids.grid.width - (snackbar.snackbar_x * 2)) / self.ids.grid.width
        snackbar.open()
