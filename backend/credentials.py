from backend.my_logger import logger


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
    """

    def __init__(self, site=None, username=None, password=None):
        self.site = site
        self.username = username
        self.password = password

    def get_credentials(self):
        logger.info("Getting credentials.")
        return list((self.site, self.username, self.password))

    def update_site(self, site):
        logger.info("Updating site to {}".format(site))
        self.site = site

    def update_username(self, username):
        logger.info("Updating username to {}".format(username))
        self.username = username

    def update_password(self, password):
        logger.info("Updating password.")
        self.password = password

    def __del__(self):
        logger.info("Credentials object deleted from memory.")
