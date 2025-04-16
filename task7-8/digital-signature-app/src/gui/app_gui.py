from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os
from datetime import datetime
from crypto.key_generation import generate_keys
from crypto.signing import sign_message
from crypto.verification import verify_signature
from utils.file_operations import save_to_file, load_from_file, save_key_to_file
from utils.logging_util import log_event

class AppGUI(QtWidgets.QWidget):  # Renamed from DigitalSignatureApp to AppGUI
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Digital Signature Application')
        self.setGeometry(100, 100, 600, 400)

        # Algorithm Selection
        self.algorithm_label = QtWidgets.QLabel('Select Algorithm:')
        self.algorithm_combo = QtWidgets.QComboBox()
        self.algorithm_combo.addItems(['RSA', 'ElGamal', 'DSA'])

        # Hashing Algorithm Selection
        self.hashing_label = QtWidgets.QLabel('Select Hashing Algorithm:')
        self.hashing_combo = QtWidgets.QComboBox()
        self.hashing_combo.addItems(['SHA-256', 'SHA-384', 'SHA-512'])

        # Key Generation Section
        self.key_gen_button = QtWidgets.QPushButton('Generate Keys')
        self.key_gen_button.clicked.connect(self.generate_keys)
        self.keys_display = QtWidgets.QTextEdit(self)
        self.keys_display.setReadOnly(True)
        self.save_keys_button = QtWidgets.QPushButton('Save Keys')
        self.save_keys_button.clicked.connect(self.save_keys)

        # Signing Section
        self.message_input = QtWidgets.QTextEdit(self)
        self.sign_button = QtWidgets.QPushButton('Sign Message')
        self.sign_button.clicked.connect(self.sign_message)

        # Verification Section
        self.verify_button = QtWidgets.QPushButton('Verify Signature')
        self.verify_button.clicked.connect(self.verify_signature)

        # Layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.algorithm_label)
        layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.hashing_label)
        layout.addWidget(self.hashing_combo)
        layout.addWidget(self.key_gen_button)
        layout.addWidget(QtWidgets.QLabel('Generated Keys:'))
        layout.addWidget(self.keys_display)
        layout.addWidget(self.save_keys_button)
        layout.addWidget(QtWidgets.QLabel('Message to Sign:'))
        layout.addWidget(self.message_input)
        layout.addWidget(self.sign_button)
        layout.addWidget(self.verify_button)

        self.setLayout(layout)

    def generate_keys(self):
        algorithm = self.algorithm_combo.currentText()
        self.private_key, self.public_key = generate_keys(algorithm)
        log_event(f'Generated keys for {algorithm}')
        self.keys_display.setText(f"Private Key:\n{self.private_key}\n\nPublic Key:\n{self.public_key}")

    def save_keys(self):
        algorithm = self.algorithm_combo.currentText()
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

        # Generate filenames
        private_key_filename = f"{algorithm}_privateKey_{timestamp}.pem"
        public_key_filename = f"{algorithm}_publicKey_{timestamp}.pem"

        # Create directories if they don't exist
        private_keys_dir = os.path.join(os.getcwd(), "private_keys")
        public_keys_dir = os.path.join(os.getcwd(), "public_keys")
        os.makedirs(private_keys_dir, exist_ok=True)
        os.makedirs(public_keys_dir, exist_ok=True)

        # Save keys to respective directories
        private_key_path = os.path.join(private_keys_dir, private_key_filename)
        public_key_path = os.path.join(public_keys_dir, public_key_filename)

        save_key_to_file(self.private_key, private_key_path)
        save_key_to_file(self.public_key, public_key_path)

        log_event(f"Private key saved to: {private_key_path}")
        log_event(f"Public key saved to: {public_key_path}")

    def sign_message(self):
        message = self.message_input.toPlainText()
        algorithm = self.algorithm_combo.currentText()
        hashing_algorithm = self.hashing_combo.currentText()

        if not hasattr(self, 'private_key'):
            QtWidgets.QMessageBox.warning(self, "Error", "Private key not generated or loaded.")
            return

        # Generate the signature
        signature = sign_message(message, self.private_key, hashing_algorithm)
        log_event(f'Message signed using {algorithm} and {hashing_algorithm}')

        # Display the signature
        self.keys_display.setText(f"Generated Signature:\n{signature.hex()}")

        # Generate filenames
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        message_filename = f"{algorithm}_message_{timestamp}.txt"
        signature_filename = f"{algorithm}_signature_{timestamp}.sig"

        # Create directories if they don't exist
        messages_dir = os.path.join(os.getcwd(), "messages")
        signatures_dir = os.path.join(os.getcwd(), "signatures")
        os.makedirs(messages_dir, exist_ok=True)
        os.makedirs(signatures_dir, exist_ok=True)

        # Save the message and signature
        message_path = os.path.join(messages_dir, message_filename)
        signature_path = os.path.join(signatures_dir, signature_filename)

        from utils.file_operations import save_to_file, save_signature_to_file
        save_to_file(message, message_path)
        save_signature_to_file(signature, signature_path)

        log_event(f"Message saved to: {message_path}")
        log_event(f"Signature saved to: {signature_path}")

    def verify_signature(self):
        message = self.message_input.toPlainText()
        hashing_algorithm = self.hashing_combo.currentText()

        if not hasattr(self, 'public_key'):
            QtWidgets.QMessageBox.warning(self, "Error", "Public key not generated or loaded.")
            return

        # Load the signature file
        signature_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Load Signature", "", "Signature Files (*.sig)")
        if not signature_path:
            return

        from utils.file_operations import load_signature_from_file
        signature = load_signature_from_file(signature_path)

        # Verify the signature
        is_valid = verify_signature(message, signature, self.public_key, hashing_algorithm)
        if is_valid:
            self.keys_display.setText(f"Original Message:\n{message}\n\nSignature is valid.")
            QtWidgets.QMessageBox.information(self, "Verification Result", "The signature is valid.")
            log_event("Signature verification successful.")
        else:
            self.keys_display.setText("Invalid signature.")
            QtWidgets.QMessageBox.warning(self, "Verification Result", "The signature is invalid.")
            log_event("Signature verification failed.")

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = AppGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()