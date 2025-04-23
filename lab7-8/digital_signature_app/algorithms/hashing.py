# Hashing Wrapper for SHA-256, SHA-384, SHA-512

import hashlib

def hash_message(message, algorithm="SHA-256"):
    """
    Hash a message using the specified algorithm.
    Supported algorithms: SHA-256, SHA-384, SHA-512.
    """
    if algorithm == "SHA-256":
        hasher = hashlib.sha256()
    elif algorithm == "SHA-384":
        hasher = hashlib.sha384()
    elif algorithm == "SHA-512":
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")
    
    hasher.update(message.encode())
    return int(hasher.hexdigest(), 16)
