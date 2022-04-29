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
        """
        Initializes credentials
        Args:
            site: website
            username: username
            password: password
        """
        self.site = site
        self.username = username
        self.password = password

    def get_credentials(self):
        """
        Get credentials to be viewed.
        Returns:
            List of credentials.
        """
        logger.info("Getting credentials.")
        return list((self.site, self.username, self.password))

    def __del__(self):
        """
        Destructs credentials object.
        """
        logger.info("Credentials object deleted from memory.")
