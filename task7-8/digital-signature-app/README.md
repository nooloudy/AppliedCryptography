# Digital Signature Application

This project is a digital signature application that allows users to create and verify digital signatures using various algorithms and hashing methods. The application features a user-friendly graphical interface and supports multiple digital signature algorithms and SHA hashing algorithms.

## Features

- **Digital Signature Algorithm Selection**: Choose from RSA, ElGamal, or DSA for signing messages.
- **Hashing Algorithm Selection**: Select from SHA-256, SHA-384, or SHA-512 for hashing messages before signing.
- **Key Generation**: Generate public and private key pairs for the selected algorithm.
- **Digital Signature Creation**: Sign messages and display the generated digital signature.
- **Digital Signature Verification**: Verify signatures against the original messages.
- **File Operations**: Load and save keys, messages, and signatures to files.
- **Logging**: Track operations and errors throughout the application.

## Project Structure

```
digital-signature-app
├── src
│   ├── algorithms
│   │   ├── rsa.py
│   │   ├── elgamal.py
│   │   └── dsa.py
│   ├── hashing
│   │   ├── sha256.py
│   │   ├── sha384.py
│   │   └── sha512.py
│   ├── gui
│   │   ├── main_window.py
│   │   └── styles.py
│   ├── utils
│   │   ├── file_operations.py
│   │   └── logging.py
│   ├── app.py
│   └── __init__.py
├── tests
│   ├── test_algorithms.py
│   ├── test_hashing.py
│   ├── test_file_operations.py
│   └── test_gui.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
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

1. Run the application:
   ```
   python src/app.py
   ```
2. Use the GUI to select algorithms, generate keys, sign messages, and verify signatures.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.