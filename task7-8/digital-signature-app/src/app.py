from tkinter import Tk
from gui.main_window import MainWindow

def main():
    root = Tk()
    root.title("Digital Signature Application")
    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()