# RSA GUI Application

This project implements the RSA algorithm for encrypting and decrypting messages with a graphical user interface (GUI). The application allows users to generate RSA keys, encrypt plaintext, and decrypt ciphertext, all through an intuitive interface.

## Project Structure

```
rsa-gui-app
├── src
│   ├── main.py               # Entry point of the application
│   ├── rsa_algorithm.py      # Implementation of the RSA algorithm
│   ├── gui.py                # GUI layout and event handling
│   ├── utils
│   │   ├── file_operations.py # Utility functions for file operations
│   │   └── logger.py         # Logging functions for operations and errors
├── requirements.txt          # Project dependencies
├── README.md                 # Project documentation
└── .gitignore                # Files and directories to ignore in version control
```

## Features

- **Key Generation**: Generate and display public and private keys, with options to save them to files.
- **Encryption**: Input plaintext, encrypt it using the public key, and display the encrypted text with an option to save it.
- **Decryption**: Input encrypted text, decrypt it using the private key, and display the decrypted text with an option to save it.
- **User-Friendly GUI**: Built using Tkinter or PyQt for an intuitive user experience.
- **File Operations**: Load and save text and key files easily.
- **Logging**: All operations are logged to a separate file for tracking and debugging.

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd rsa-gui-app
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   python src/main.py
   ```

2. Use the GUI to generate keys, encrypt messages, and decrypt ciphertext.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.