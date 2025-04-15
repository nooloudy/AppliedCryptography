from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keys(key_size=2048):
    """Generate RSA key pair."""
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')  # Export private key in PEM format
    public_key = key.publickey().export_key().decode('utf-8')  # Export public key in PEM format
    return {"private_key": private_key, "public_key": public_key}

def save_key(key, filepath):
    """Save a key (public or private) to a file."""
    with open(filepath, "w") as file:
        file.write(key)

def load_key(filepath):
    """Load a key (public or private) from a file."""
    with open(filepath, "r") as file:
        return file.read()

def sign_message(private_key, hashed_message):
    """Sign a hashed message using RSA."""
    key = RSA.import_key(private_key)  # Import the private key
    signature = pkcs1_15.new(key).sign(SHA256.new(hashed_message))  # Sign the hash
    return signature

def verify_signature(public_key, hashed_message, signature):
    """Verify an RSA signature."""
    key = RSA.import_key(public_key)  # Import the public key
    try:
        pkcs1_15.new(key).verify(SHA256.new(hashed_message), signature)  # Verify the signature
        return True
    except (ValueError, TypeError):
        return False