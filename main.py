from backend.my_logger import logger
from backend.password_manager import PasswordManager
from frontend.pm_app import PasswordManagerApp


def main():
    """
    The main function of the password manager.
    """
    try:
        password_manager = PasswordManager()
        PasswordManagerApp(password_manager).run()
    except Exception as e:
        logger.error("Exception occurred in main(). {}".format(e))
        return None


if __name__ == "__main__":
    main()
