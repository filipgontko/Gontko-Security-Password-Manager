from kivy.uix.screenmanager import Screen

from backend.password_manager import generate_password


class LoggedIn(Screen):
    """
    Screen showing list of stored credentials.
    On this screen it is possible to add new credentials, and generate passwords.
    """
    def __init__(self, password_manager):
        """
        Initialize LoggedIn view.
        Args:
            password_manager: Password manager object
        """
        super(LoggedIn, self).__init__()
        self.password_manager = password_manager

    def on_enter(self):
        """
        Initialize text fields when entering the view.
        """
        self.ids.search_field.text = "\r"
        self.ids.search_field.text = ""

    def on_leave(self):
        """
        Clear the text fields, password generator and set password field to show masked password when leaving the view.
        """
        self.ids.search_field.text = ""
        self.ids.website.text = ""
        self.ids.username.text = ""
        self.ids.passwd.text = ""
        self.ids.generate_pwd.text = ""
        self.ids.strength_slider.value = 12
        self.ids.passwd.password = True
        self.ids.eye_icon.icon = "eye-off"

    def logout(self):
        """
        Log out of the password manager.
        """
        self.password_manager.logout()

    def view_credentials(self, credential_id, website, username):
        """
        View credentials user clicked on. This will take the user to the CredentialsView.
        Args:
            credential_id: ID of the credential.
            website: Website.
            username: Username.
        """
        self.parent.current = "creds_view"
        self.parent.transition.direction = "left"
        self.password_manager.credential_id = credential_id
        self.password_manager.credential_site = website
        self.password_manager.credential_username = username

    def add_credentials(self, site, username, password):
        """
        Add credentials to the database.
        Args:
            site: Website.
            username: Username.
            password: Password.
        """
        self.password_manager.add_new_credentials(site, username, password)

    def generate_password(self, length=12):
        """
        Generate a strong password.
        Args:
            length: Length of the password (minimum length is 12 characters).

        Returns:
            Password string.
        """
        return generate_password(length)

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
                        self.add_credential_item(creds[0], creds[1], creds[2])
                else:
                    self.add_credential_item(creds[0], creds[1], creds[2])
        except Exception as e:
            return None

    def add_credential_item(self, cred_id, website, username):
        """
        Adding credentials to the search list.
        Args:
            cred_id: ID of credentials.
            website: Website.
            username: Username.
        """
        self.ids.rv.data.append(
            {
                "viewclass": "CustomTwoLineCredsListItem",
                "text": website,
                "secondary_text": "username: {}".format(username),
                "on_release": lambda: self.view_credentials(cred_id, website, username),
                "callback": lambda x: x
            }
        )
