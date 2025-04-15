def sha256_hash(message: str) -> str:
    import hashlib
    # Create a new sha256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the bytes of the message
    sha256.update(message.encode('utf-8'))
    # Return the hexadecimal representation of the digest
    return sha256.hexdigest()