import sys
from PyQt6.QtWidgets import QApplication, QDialog
from ui_dialog import *


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_LoginPage()
        self.ui.setupUi(self)

        self.ui.buttonBox.accepted.connect(self.handle_login)

    def handle_login(self):
        username = self.ui.username.text()
        password = self.ui.password.text()

        if username == "admin" and password == "password123":
            print("Login successful")
            self.accept()
        else:
            print("Invalid login")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginDialog()
    window.show()
    sys.exit(app.exec())