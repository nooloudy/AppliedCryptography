def sha384_hash(message: str) -> str:
    import hashlib
    # Create a new sha384 hash object
    sha384 = hashlib.sha384()
    # Update the hash object with the bytes-like object (message)
    sha384.update(message.encode('utf-8'))
    # Return the hexadecimal representation of the digest
    return sha384.hexdigest()