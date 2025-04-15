from Crypto.PublicKey import RSA

def generate_keys(key_size=2048):
    """Generate RSA key pair."""
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')  # Export private key in PEM format
    public_key = key.publickey().export_key().decode('utf-8')  # Export public key in PEM format
    return {"private_key": private_key, "public_key": public_key}

def sign_message(private_key, message):
    """Sign a message using RSA."""
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    key = RSA.import_key(private_key)  # Import the private key
    hashed_message = SHA256.new(message.encode())  # Hash the message
    signature = pkcs1_15.new(key).sign(hashed_message)  # Sign the hash
    return signature

def verify_signature(public_key, message, signature):
    """Verify an RSA signature."""
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    key = RSA.import_key(public_key)  # Import the public key
    hashed_message = SHA256.new(message.encode())  # Hash the message
    try:
        pkcs1_15.new(key).verify(hashed_message, signature)  # Verify the signature
        return True
    except (ValueError, TypeError):
        return False