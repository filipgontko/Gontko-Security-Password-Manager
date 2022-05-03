from kivy.uix.screenmanager import Screen
from kivymd.uix.dialog import MDDialog

from backend.crypto import check_if_pwned
from backend.my_logger import logger
from backend.password_manager import generate_password


class LoggedIn(Screen):
    """
    Screen showing list of stored credentials.
    On this screen it is possible to add new credentials, and generate passwords.
    """
    def __init__(self, password_manager):
        """
        Initialize LoggedIn screen.
        Args:
            password_manager: Password manager object.
        """
        super(LoggedIn, self).__init__()
        self.password_manager = password_manager
        self.dialog = None

    def on_enter(self):
        """
        Initialize text fields when entering the view.
        """
        try:
            self.refresh_search()
        except Exception as e:
            logger.error("Exception occurred during on_enter(). {}".format(e))

    def on_leave(self):
        """
        Clear the text fields, password generator and set password field to show masked password when leaving the view.
        """
        try:
            self.ids.search_field.text = ""
            self.ids.cred_name.text = ""
            self.ids.website.text = ""
            self.ids.username.text = ""
            self.ids.passwd.text = ""
            self.ids.generate_pwd.text = ""
            self.ids.strength_slider.value = 12
            self.ids.passwd.password = True
            self.ids.eye_icon.icon = "eye-off"
        except Exception as e:
            logger.error("Exception occurred during on_leave(). {}".format(e))

    def logout(self):
        """
        Log out of the password manager.
        """
        try:
            self.password_manager.logout()
        except Exception as e:
            logger.error("Exception occurred during logout(). {}".format(e))

    def view_credentials(self, credential_id, name, website, username):
        """
        View credentials user clicked on. This will take the user to the CredentialsView.
        Args:
            credential_id: ID of the credential.
            name: Name of the credential.
            website: Website.
            username: Username.
        """
        try:
            self.parent.current = "creds_view"
            self.parent.transition.direction = "left"
            self.password_manager.credential_name = name
            self.password_manager.credential_id = credential_id
            self.password_manager.credential_site = website
            self.password_manager.credential_username = username
        except Exception as e:
            logger.error("Exception occurred during view_credentials(). {}".format(e))

    def add_credentials(self, name, site, username, password):
        """
        Add credentials to the database.
        Args:
            name: Credential name.
            site: Website.
            username: Username.
            password: Password.
        """
        try:
            self.is_pwned_message()
            self.password_manager.add_new_credentials(name, site, username, password)
            self.ids.cred_name.text = ""
            self.ids.website.text = ""
            self.ids.username.text = ""
            self.ids.passwd.text = ""
            self.ids.generate_pwd.text = ""
            self.refresh_search()
        except Exception as e:
            logger.error("Exception occurred while add_credentials(). {}".format(e))

    def refresh_search(self):
        """
        Refresh the list of credentials in DB.
        """
        try:
            self.ids.search_field.text = "\r"
            self.ids.search_field.text = ""
        except Exception as e:
            logger.error("Exception occurred while refresh_search(). {}".format(e))

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

    def set_list_credentials(self, text="", search=True):
        """
        Prepare a list of existing credentials to be shown and searched in.
        Args:
            text: Credential name to be searched for.
            search: True if searching, False to show all credentials.
        """
        self.ids.rv.data = []
        try:
            for creds in self.password_manager.get_all_credentials():
                if search:
                    if text in creds[1]:
                        self.add_credential_item(creds[0], creds[1], creds[2], creds[3])
                else:
                    self.add_credential_item(creds[0], creds[1], creds[2], creds[3])
        except Exception as e:
            return None

    def add_credential_item(self, cred_id, name, website, username):
        """
        Adding credentials to the search list.
        Args:
            name: Name of the credential.
            cred_id: ID of credentials.
            website: Website.
            username: Username.
        """
        try:
            self.ids.rv.data.append(
                {
                    "viewclass": "CustomTwoLineCredsListItem",
                    "text": name,
                    "secondary_text": "username: {}".format(username),
                    "on_release": lambda: self.view_credentials(cred_id, name, website, username),
                    "callback": lambda x: x
                }
            )
        except Exception as e:
            logger.error("Exception occurred during add_credential_item(). {}".format(e))

    def is_pwned_message(self):
        """
        Shows a dialog with a message that the password had been pwned!
        """
        try:
            if check_if_pwned(self.ids.passwd.text):
                self.dialog = MDDialog(text="OOOPS! Your password has been pwned! Change it now")
                self.dialog.open()
                self.dialog = None
        except Exception as e:
            logger.error("Exception occurred during showing pwned dialog. {}".format(e))
