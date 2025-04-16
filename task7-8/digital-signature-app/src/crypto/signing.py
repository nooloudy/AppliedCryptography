import hashlib


def create_signature(private_key, message, hashing_algorithm):
    # Hash the message using the selected hashing algorithm
    if hashing_algorithm == 'SHA-256':
        hash_func = hashlib.sha256()
    elif hashing_algorithm == 'SHA-384':
        hash_func = hashlib.sha384()
    elif hashing_algorithm == 'SHA-512':
        hash_func = hashlib.sha512()
    else:
        raise ValueError("Unsupported hashing algorithm")

    hash_func.update(message.encode())
    hashed_message = hash_func.digest()

    # Create the signature using the private key
    signature = private_key.sign(hashed_message)

    return signature


def save_signature(signature, file_path):
    with open(file_path, 'wb') as sig_file:
        sig_file.write(signature)


def load_signature(file_path):
    with open(file_path, 'rb') as sig_file:
        return sig_file.read()


def sign_message(message, private_key, hashing_algorithm='SHA-256'):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, dsa, ec
    from utils.logging_util import log_event, log_error

    # Select the hash algorithm
    if hashing_algorithm == 'SHA-256':
        hash_algorithm = hashes.SHA256()
    elif hashing_algorithm == 'SHA-384':
        hash_algorithm = hashes.SHA384()
    elif hashing_algorithm == 'SHA-512':
        hash_algorithm = hashes.SHA512()
    else:
        raise ValueError("Unsupported hashing algorithm")

    try:
        # Create the signature using the private key
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hash_algorithm
            )
        elif isinstance(private_key, dsa.DSAPrivateKey):
            signature = private_key.sign(
                message.encode(),
                hash_algorithm
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                message.encode(),
                ec.ECDSA(hash_algorithm)
            )
        else:
            raise TypeError("Unsupported private key type")

        log_event("Message signed successfully.")
        return signature
    except Exception as e:
        log_error(f"Signing failed: {e}")
        raise