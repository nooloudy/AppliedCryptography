def verify_signature(message, signature, public_key, hashing_algorithm):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec, dsa
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
        # Verify the signature
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(hash_algorithm)
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(
                signature,
                message.encode(),
                hash_algorithm
            )
        else:
            public_key.verify(
                signature,
                message.encode(),
                padding.PKCS1v15(),
                hash_algorithm
            )
        log_event("Signature verification successful.")
        return True
    except Exception as e:
        log_error(f"Signature verification failed: {e}")
        return False