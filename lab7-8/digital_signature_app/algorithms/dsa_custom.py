# DSA Digital Signature Algorithm Implementation (Sign/Verify)

import random
import hashlib
from algorithms.hashing import hash_message

# --- Utilities ---
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Расширенный алгоритм Евклида"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def is_prime(n, k=5):
    """Тест Миллера-Рабина"""
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
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
    while True:
        p = random.getrandbits(bits)
        p |= 1
        if is_prime(p):
            return p

# --- DSA Key Generation ---
def generate_keys(L=512, N=160):
    """L — size of p, N — size of q"""
    while True:
        q = generate_prime(N)
        for _ in range(10_000):
            k = random.getrandbits(L - N)
            p = q * k + 1
            if is_prime(p):
                break
        else:
            continue
        break

    h = 2
    g = pow(h, (p - 1) // q, p)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return (p, q, g), y, x  # Return public parameters (p, q, g), public key (y), and private key (x)

# --- DSA Signing ---
def sign_message(private_key, message, public_params, algorithm="SHA-256"):
    p, q, g = public_params
    x = private_key
    h = hash_message(message, algorithm) % q
    while True:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        try:
            k_inv = modinv(k, q)
        except:
            continue
        s = (k_inv * (h + x * r)) % q
        if s != 0:
            break
    return r, s

# --- DSA Verification ---
def verify_signature(public_key, message, signature, public_params, algorithm="SHA-256"):
    p, q, g = public_params
    y = public_key
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    h = hash_message(message, algorithm) % q
    w = modinv(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r
