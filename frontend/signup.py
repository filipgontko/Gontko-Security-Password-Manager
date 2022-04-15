from kivy.uix.screenmanager import Screen, SlideTransition


class Signup(Screen):
    def signup(self, email, password):
        self.password_manager.sign_up(email, password)
        self.root.ids.email.text = ""
        self.root.ids.password.text = ""
        self.manager.transition = SlideTransition(direction="left")
        # TODO: Change to connected
        self.manager.current = "login"
        self.manager.get_screen('login')

    def logout(self):
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = 'login'
        self.manager.get_screen('login')
