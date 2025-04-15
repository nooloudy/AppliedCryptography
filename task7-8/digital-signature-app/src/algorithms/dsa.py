from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_keys(key_size=2048):
    """Generate DSA key pair."""
    key = DSA.generate(key_size)
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
    """Sign a hashed message using DSA."""
    key = DSA.import_key(private_key)  # Import the private key
    signer = DSS.new(key, 'fips-186-3')  # Create a DSA signer
    signature = signer.sign(SHA256.new(hashed_message))  # Sign the hash
    return signature

def verify_signature(public_key, hashed_message, signature):
    """Verify a DSA signature."""
    key = DSA.import_key(public_key)  # Import the public key
    hashed = SHA256.new(hashed_message)  # Wrap the hashed message
    verifier = DSS.new(key, 'fips-186-3')  # Create a DSA verifier
    try:
        verifier.verify(hashed, signature)  # Verify the signature
        return True
    except (ValueError, TypeError):
        return False