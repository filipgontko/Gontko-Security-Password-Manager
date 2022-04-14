from kivy.uix.screenmanager import Screen, SlideTransition


class Login(Screen):
    def __init__(self, password_manager):
        super().__init__()
        self.password_manager = password_manager

    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"

    def login(self, email, password):
        self.password_manager.login(email, password)
        self.root.ids.email.text = ""
        self.root.ids.password.text = ""
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "login"

    def forgot_password(self):
        pass
