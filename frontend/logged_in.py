from kivy.uix.screenmanager import Screen


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