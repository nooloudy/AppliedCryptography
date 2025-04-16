from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dsa_key_pair(key_size=2048):
    private_key = dsa.generate_private_key(
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_elgamal_key_pair(key_size=2048):
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_keys(algorithm, key_size=2048):
    if algorithm == 'RSA':
        return generate_rsa_key_pair(key_size)
    elif algorithm == 'DSA':
        return generate_dsa_key_pair(key_size)
    elif algorithm == 'ElGamal':
        return generate_elgamal_key_pair(key_size)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def save_key_to_file(key, file_path):
    if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, dsa.DSAPrivateKey):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL
        )
    else:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.Raw
        )
    
    with open(file_path, 'wb') as key_file:
        key_file.write(pem)

def display_keys(private_key, public_key):
    print("Private Key:")
    print(private_key)
    print("\nPublic Key:")
    print(public_key)