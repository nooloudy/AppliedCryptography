from Crypto.Util import number
from Crypto.Hash import SHA256
import json  # Add import for JSON serialization
import base64  # Add import for Base64 encoding/decoding

def generate_keys(key_size=2048):
    """Generate ElGamal key pair."""
    p = number.getPrime(key_size)  # Generate a large prime number
    g = number.getRandomRange(2, p - 1)  # Generate a generator
    x = number.getRandomRange(1, p - 1)  # Private key
    y = pow(g, x, p)  # Public key

    # Serialize keys as JSON strings
    private_key = json.dumps({"p": p, "g": g, "x": x})
    public_key = json.dumps({"p": p, "g": g, "y": y})

    return {"private_key": private_key, "public_key": public_key}

def save_key(key, filepath):
    """Save a key (public or private) to a file."""
    with open(filepath, "w") as file:
        file.write(str(key))

def load_key(filepath):
    """Load a key (public or private) from a file."""
    with open(filepath, "r") as file:
        return json.loads(file.read())  # Safely parse JSON string

def sign_message(private_key_json, hashed_message):
    """Sign a hashed message using ElGamal."""
    from math import gcd

    private_key = json.loads(private_key_json)  # Deserialize JSON string
    p, g, x = private_key["p"], private_key["g"], private_key["x"]

    # Generate a random value k that is coprime with (p - 1)
    while True:
        k = number.getRandomRange(1, p - 1)
        if gcd(k, p - 1) == 1:  # Ensure k is coprime with (p - 1)
            break

    r = pow(g, k, p)  # Compute r
    k_inv = number.inverse(k, p - 1)  # Compute modular inverse of k
    hashed_int = int.from_bytes(SHA256.new(hashed_message).digest(), byteorder='big')  # Convert hash to integer
    s = (k_inv * (hashed_int - x * r)) % (p - 1)  # Compute s
    return {"r": r, "s": s}

def verify_signature(public_key_json, hashed_message, signature):
    """Verify an ElGamal signature."""
    public_key = json.loads(public_key_json)  # Deserialize JSON string
    p, g, y = public_key["p"], public_key["g"], public_key["y"]
    r, s = signature["r"], signature["s"]

    if not (0 < r < p and 0 < s < p - 1):  # Check validity of r and s
        return False

    # Ensure hashed_message is bytes
    if not isinstance(hashed_message, bytes):
        raise TypeError("hashed_message must be a bytes-like object")

    hashed_int = int.from_bytes(hashed_message, byteorder='big')  # Convert hash to integer
    v1 = pow(g, hashed_int, p)  # Compute g^H(m) mod p
    v2 = (pow(y, r, p) * pow(r, s, p)) % p  # Compute y^r * r^s mod p
    return v1 == v2