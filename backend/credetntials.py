

class Credentials:
    """
    Class representing credentials (site, username, password).

    Attributes:
        site: Site
        username: Username
        password: Password

    Methods:
        get_credentials: Retrieves credentials in a list.
        update_site: Update site.
        update_username: Update username.
        update_password: Update password.
        remove_credentials: Remove credentials.
    """

    def __init__(self, site=None, username=None, password=None):
        self.site = site
        self.username = username
        self.password = password

    def get_credentials(self):
        return list((self.site, self.username, self.password))

    def update_site(self, site):
        pass

    def update_username(self, username):
        pass

    def update_password(self, password):
        pass

    def remove_credentials(self, site, username, password):
        pass
