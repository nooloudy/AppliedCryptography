def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_file(file_path, data):
    with open(file_path, 'w') as file:
        file.write(data)

def save_encrypted_file(file_path, encrypted_data):
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def bytes_to_hex(byte_data):
    return byte_data.hex()

def read_key_file(file_path):
    return hex_to_bytes(read_file(file_path).strip())

def read_plaintext_file(file_path):
    return read_file(file_path).strip()