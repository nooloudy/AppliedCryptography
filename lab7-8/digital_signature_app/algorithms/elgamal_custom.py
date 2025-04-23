# ElGamal Digital Signature Algorithm Implementation (Sign/Verify)

import random
import hashlib
from algorithms.hashing import hash_message

# --- Utilities ---
def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Modular Inverse using Extended Euclidean Algorithm"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_prime(bits=64):
    """Generate a prime number with given bits"""
    while True:
        p = random.getrandbits(bits)
        p |= 1  # Ensure it's odd
        if is_prime(p):
            return p

# --- ElGamal Key Generation ---
def generate_keys(bits=64):
    p = generate_prime(bits)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

# --- ElGamal Signing ---
def sign_message(private_key, message, public_params, algorithm="SHA-256"):
    p, g = public_params[:2]
    x = private_key
    h = hash_message(message, algorithm)
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s

# --- ElGamal Verification ---
def verify_signature(public_key, message, signature, public_params, algorithm="SHA-256"):
    p, g, y = public_params
    r, s = signature
    if not (0 < r < p):
        return False
    h = hash_message(message, algorithm)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2
