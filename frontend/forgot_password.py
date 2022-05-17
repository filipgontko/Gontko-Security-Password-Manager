from kivy.uix.screenmanager import Screen
from kivymd.uix.button import MDRoundFlatButton, MDFillRoundFlatButton
from kivymd.uix.dialog import MDDialog

from backend.crypto import chacha20_encrypt
from backend.my_logger import logger


class ForgotPassword(Screen):
    """
    Forgot password screen where user can reset master password to the password manager.
    """
    def __init__(self, password_manager):
        """
        Initialize ForgotPassword screen.
        Args:
            password_manager: Password manager object.
        """
        super(ForgotPassword, self).__init__()
        self.password_manager = password_manager
        self.dialog = None

    def on_leave(self):
        """
        Clear the text fields, strength meter, check if pawned and set password field to show masked password
        when leaving the view.
        """
        try:
            self.ids.username.text = ""
            self.ids.new_master_password.text = ""
            self.ids.otp.text = ""
        except Exception as e:
            logger.error("Exception occurred during on_leave(). {}".format(e))

    def show_dialog(self):
        """
        Show dialog on screen.
        """
        try:
            self.dialog = None
            if not self.dialog:
                self.dialog = MDDialog(
                    title="Reset master password?",
                    text="Are you sure you want to reset master password? "
                         "You won't be able to decrypt already saved passwords.",
                    buttons=[
                        MDRoundFlatButton(text="CANCEL", on_release=self.close_dialog),
                        MDFillRoundFlatButton(text="RESET", on_release=self.reset)
                    ],
                )
            self.dialog.open()
        except Exception as e:
            logger.error("Exception occurred during show_dialog(). {}".format(e))

    def close_dialog(self, obj):
        """
        Close the dialog and set it to None.
        Args:
            obj: Dialog object.
        """
        try:
            self.dialog.dismiss()
            self.dialog = None
        except Exception as e:
            logger.error("Exception occurred while closing dialog. {}".format(e))

    def reset(self, obj):
        """
        Reset password to the password manager.
        """
        try:
            self.dialog.dismiss()
            self.dialog = None
            password = chacha20_encrypt(self.ids.new_master_password.text)
            if self.password_manager.reset_password(self.ids.username.text, password, self.ids.otp.text):
                self.parent.current = "logged_in"
                self.parent.transition.direction = "left"
                self.ids.username.text = ""
                self.ids.otp.text = ""
                self.ids.new_master_password.text = ""
        except Exception as e:
            logger.error("Exception occurred during reset(). {}".format(e))
