from kivy.uix.screenmanager import Screen

from backend.crypto import generate_otp_url, generate_otp_qr_for_auth, chacha20_encrypt, generate_crypto_key_base, \
    get_keyring_password
from backend.my_logger import logger


def password_less_setup():
    """
    Setup environment variable for PASSWORDLESS=true and generate a crypto key which will be used instead of a
    master password. This key will be stored encrypted in keychain.
    """
    with open("password_manager.env", "a") as env:
        env.write("PASSWORDLESS=true\n")
    generate_crypto_key_base("password-less")


class Signup(Screen):
    """
    Signup screen where user can sign up to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize Signup screen.
        Args:
            password_manager: Password manager object.
        """
        super(Signup, self).__init__()
        self.password_manager = password_manager
        self.original_color = None

    def signup(self, username, password, switch):
        """
        Sign up the user to the password manager.
        Args:
            username: Username of the user.
            password: Master password.
            switch: Password-less switch value
        """
        try:
            if username != "":
                # Password-less
                if switch:
                    password_less_setup()
                    password = chacha20_encrypt(get_keyring_password("password-less"))
                    self.signup_with_mfa(username, password)
                # With password
                if password != "":
                    password = chacha20_encrypt(password)
                    self.signup_with_mfa(username, password)
        except Exception as e:
            logger.error("Exception occurred during signup. {}".format(e))

    def signup_with_mfa(self, username, password):
        """
        Add entries to Master key DB and continue to MFA setup screen.
        Returns:
            None
        """
        if self.password_manager.sign_up(username, password):
            self.setup_mfa()
            return None

    def setup_mfa(self):
        """
        Generate OTP for user as MFA.
        """
        try:
            url = generate_otp_url(self.password_manager.username)
            generate_otp_qr_for_auth(url)
            self.parent.current = "mfa"
            self.parent.transition.direction = "left"
        except Exception as e:
            logger.error("Exception occurred during setting up MFA. {}".format(e))

    def password_less_switch(self, switch_object, switch_value, color):
        """
        Switch that enables password-less signup. If is active, master password input is disabled.
        Args:
            switch_object: Switch object
            switch_value: Value from the switch (True if active, False if inactive)
            color: Original color of the password text box
        """
        try:
            if color != [0, 0, 0, 1]:
                self.original_color = color

            if switch_value:
                self.ids.password.disabled = True
                self.ids.password.normal_color = [0, 0, 0, 1]
            else:
                self.ids.password.disabled = False
                self.ids.password.normal_color = self.original_color
        except Exception as e:
            logger.error("Exception occurred when switching password-less. - {}".format(e))