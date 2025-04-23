# RSA Digital Signature Algorithm Implementation (Sign/Verify)

import random
from algorithms.hashing import hash_message

# --- Utilities ---
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Modular Inverse using Extended Euclidean Algorithm"""
    m0, x0, x1 = m, 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Generate a prime number with given bits"""
    while True:
        p = random.getrandbits(bits)
        p |= 1
        if is_prime(p):
            return p

# --- RSA key generation ---
def generate_keys(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)

    return (n, e), (n, d)

# --- RSA Signing ---
def sign_message(private_key, message, algorithm="SHA-256"):
    n, d = private_key
    h = hash_message(message, algorithm)
    signature = pow(h, d, n)
    return signature

# --- RSA Verification ---
def verify_signature(public_key, message, signature, algorithm="SHA-256"):
    n, e = public_key
    h = hash_message(message, algorithm)
    h_from_signature = pow(signature, e, n)
    return h == h_from_signature
