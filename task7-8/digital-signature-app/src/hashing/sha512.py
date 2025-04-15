import hashlib

def hash_message(message: str) -> str:
    """Hashes a message using SHA-512 algorithm."""
    sha512_hash = hashlib.sha512()
    sha512_hash.update(message.encode('utf-8'))
    return sha512_hash.hexdigest()