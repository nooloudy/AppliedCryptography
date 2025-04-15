from Crypto.Util import number
from Crypto.Hash import SHA256

def generate_keys(key_size=2048):
    """Generate ElGamal key pair."""
    p = number.getPrime(key_size)  # Generate a large prime number
    g = number.getRandomRange(2, p - 1)  # Generate a generator
    x = number.getRandomRange(1, p - 1)  # Private key
    y = pow(g, x, p)  # Public key
    private_key = {"p": p, "g": g, "x": x}  # Private key components
    public_key = {"p": p, "g": g, "y": y}  # Public key components
    return {"private_key": private_key, "public_key": public_key}

def sign_message(private_key, message):
    """Sign a message using ElGamal."""
    from math import gcd

    p, g, x = private_key["p"], private_key["g"], private_key["x"]

    # Generate a random value k that is coprime with (p - 1)
    while True:
        k = number.getRandomRange(1, p - 1)
        if gcd(k, p - 1) == 1:  # Ensure k is coprime with (p - 1)
            break

    r = pow(g, k, p)  # Compute r
    k_inv = number.inverse(k, p - 1)  # Compute modular inverse of k
    hashed_message = int.from_bytes(SHA256.new(message.encode()).digest(), byteorder='big')  # Hash the message
    s = (k_inv * (hashed_message - x * r)) % (p - 1)  # Compute s
    return {"r": r, "s": s}

def verify_signature(public_key, message, signature):
    """Verify an ElGamal signature."""
    p, g, y = public_key["p"], public_key["g"], public_key["y"]
    r, s = signature["r"], signature["s"]
    if not (0 < r < p and 0 < s < p - 1):  # Check validity of r and s
        return False
    hashed_message = int.from_bytes(SHA256.new(message.encode()).digest(), byteorder='big')  # Hash the message
    v1 = pow(g, hashed_message, p)  # Compute g^H(m) mod p
    v2 = (pow(y, r, p) * pow(r, s, p)) % p  # Compute y^r * r^s mod p
    return v1 == v2