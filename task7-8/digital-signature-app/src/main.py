# digital-signature-app/src/main.py

from PyQt5.QtWidgets import QApplication
from gui.app_gui import AppGUI
import sys

def main():
    app = QApplication(sys.argv)  # Initialize QApplication
    window = AppGUI()  # Create AppGUI instance
    window.show()
    sys.exit(app.exec_())  # Start the event loop

if __name__ == "__main__":
    main()