from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_keys(key_size=2048):
    """Generate DSA key pair."""
    key = DSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')  # Export private key in PEM format
    public_key = key.publickey().export_key().decode('utf-8')  # Export public key in PEM format
    return {"private_key": private_key, "public_key": public_key}

def sign_message(private_key, message):
    """Sign a message using DSA."""
    key = DSA.import_key(private_key)  # Import the private key
    hashed_message = SHA256.new(message.encode())  # Hash the message
    signer = DSS.new(key, 'fips-186-3')  # Create a DSA signer
    signature = signer.sign(hashed_message)  # Sign the hash
    return signature

def verify_signature(public_key, message, signature):
    """Verify a DSA signature."""
    key = DSA.import_key(public_key)  # Import the public key
    hashed_message = SHA256.new(message.encode())  # Hash the message
    verifier = DSS.new(key, 'fips-186-3')  # Create a DSA verifier
    try:
        verifier.verify(hashed_message, signature)  # Verify the signature
        return True
    except (ValueError, TypeError):
        return False