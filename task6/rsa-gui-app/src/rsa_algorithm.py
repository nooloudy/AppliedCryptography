def generate_keys(p: int, q: int):
    
    n = p * q
    z = (p - 1) * (q - 1)
    e = find_e(z)
    d = find_d(e, z)
    
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encrypt_message(public_key, message):
    e, n = public_key
    encrypted_message = [(ord(char) ** e) % n for char in message]
    return ' '.join(map(str, encrypted_message)) 


def decrypt_message(private_key, encrypted_message):
    d, n = private_key
    encrypted_numbers = list(map(int, encrypted_message.split())) 
    decrypted_message = ''.join([chr((num ** d) % n) for num in encrypted_numbers])
    return decrypted_message


def find_e(z: int):
    for e in range(2, z):
        if gcd(e, z) == 1:
            return e
    raise ValueError("Failed to find a valid 'e' value")


def find_d(e: int, z: int):
    for d in range(2, z):
        if (d * e) % z == 1:
            return d
    raise ValueError("Failed to find a valid 'd' value")


def gcd(x: int, y: int):
    while y != 0:
        x, y = y, x % y
    return x