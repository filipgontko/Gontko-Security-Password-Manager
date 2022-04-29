from backend.password_manager import PasswordManager
from frontend.pm_app import PasswordManagerApp


def main():
    """
    The main function of the password manager.
    """
    password_manager = PasswordManager()
    PasswordManagerApp(password_manager).run()


if __name__ == "__main__":
    main()
