# Configuration settings for the digital signature application

DEFAULT_KEY_LENGTH = 2048
SUPPORTED_ALGORITHMS = ['RSA', 'ElGamal', 'DSA']
SUPPORTED_HASHES = ['SHA-256', 'SHA-384', 'SHA-512']
KEYS_DIRECTORY = './keys'
SIGNATURES_DIRECTORY = './signatures'
LOG_FILE_PATH = './app.log'