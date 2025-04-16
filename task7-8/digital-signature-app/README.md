# Digital Signature Application

This project is a GUI-based Python application that allows users to create and verify digital signatures using various cryptographic algorithms and SHA hashing methods. It includes features for key generation, saving/loading keys, and file operations, along with logging and error handling.

## Features

- **Digital Signature Algorithm Selection**: Supports RSA, ElGamal, and DSA algorithms.
- **Hashing Algorithm Selection**: Options for SHA-256, SHA-384, and SHA-512.
- **Key Generation**: Generate public/private key pairs and save them to user-specified files.
- **Signature Creation**: Sign messages with selected algorithms and hashing methods.
- **Signature Verification**: Verify signatures against messages using public keys.
- **Logging**: All operations are logged to a separate log file for tracking.

## Project Structure

```
digital-signature-app
├── src
│   ├── main.py                # Entry point of the application
│   ├── gui
│   │   ├── app_gui.py         # GUI implementation
│   │   └── __init__.py        # GUI package initializer
│   ├── crypto
│   │   ├── key_generation.py   # Key generation functions
│   │   ├── signing.py          # Signature creation functions
│   │   ├── verification.py      # Signature verification functions
│   │   └── __init__.py        # Crypto package initializer
│   ├── utils
│   │   ├── file_operations.py  # File operations utilities
│   │   ├── logging_util.py     # Logging utilities
│   │   └── __init__.py        # Utils package initializer
│   └── config
│       └── settings.py        # Configuration settings
├── tests
│   ├── test_key_generation.py  # Unit tests for key generation
│   ├── test_signing.py         # Unit tests for signing
│   ├── test_verification.py     # Unit tests for verification
│   └── __init__.py            # Tests package initializer
├── requirements.txt            # Project dependencies
├── README.md                   # Project documentation
└── .gitignore                  # Files to ignore in version control
```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/digital-signature-app.git
   ```
2. Navigate to the project directory:
   ```
   cd digital-signature-app
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application using:
```
python src/main.py
```

Follow the GUI instructions to generate keys, sign messages, and verify signatures.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.