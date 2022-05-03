from backend.my_logger import logger


class Credentials:
    """
    Class representing credentials (name, site, username, password).

    Attributes:
        name: Site or App name.
        site: Site
        username: Username
        password: Password

    Methods:
        get_credentials: Retrieves credentials in a list.
    """

    def __init__(self, name=None, site=None, username=None, password=None):
        """
        Initializes credentials
        Args:
            site: website
            username: username
            password: password
        """
        self.name = name
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
        return list((self.name, self.site, self.username, self.password))

    def __del__(self):
        """
        Destructs credentials object.
        """
        logger.info("Credentials object deleted from memory.")
