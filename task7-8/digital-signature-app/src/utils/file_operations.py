from cryptography.hazmat.primitives import serialization

def save_to_file(data, file_path):
    with open(file_path, 'w') as file:
        file.write(data)

def load_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def save_key_to_file(key, file_path):
    if hasattr(key, 'private_bytes'):  # For private keys
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif hasattr(key, 'public_bytes'):  # For public keys
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise TypeError("Unsupported key type")

    with open(file_path, 'wb') as file:
        file.write(pem)

def load_key_from_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def save_signature_to_file(signature, file_path):
    with open(file_path, 'wb') as file:
        file.write(signature)
    print(f"Saved signature (hex): {signature.hex()}")  # Debugging output

def load_signature_from_file(file_path):  # Fixed the missing parenthesis
    with open(file_path, 'rb') as file:
        return file.read()