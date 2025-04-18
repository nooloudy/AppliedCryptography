import time
import csv

# S-box and other constants for AES
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

R_CON = [
    0x00,  # 0 не используется
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def mix_columns(state):
    return state

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def key_expansion(key):
    expanded_key = []
    for i in range(4):
        expanded_key.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(4, 44):
        temp = expanded_key[i - 1]
        if i % 4 == 0:
            temp = [S_BOX[temp[1]] ^ R_CON[i // 4], S_BOX[temp[2]], S_BOX[temp[3]], S_BOX[temp[0]]]
        expanded_key.append([expanded_key[i - 4][j] ^ temp[j] for j in range(4)])

    return expanded_key

def aes_encrypt_block(block, key):
    state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = block[i * 4 + j]

    expanded_key = key_expansion(key)
    state = add_round_key(state, expanded_key[:4])

    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded_key[round * 4:(round + 1) * 4])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded_key[40:])

    encrypted_block = [state[j][i] for i in range(4) for j in range(4)]
    return encrypted_block

def encrypt(plaintext, key):
    ciphertext = []
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        if len(block) < 16:
            block += [0] * (16 - len(block))
        ciphertext.extend(aes_encrypt_block(block, key))
    return ciphertext

def encrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'r') as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f"Error: The file {input_file} does not exist.")
        return

    start_time = time.time()
    ciphertext = encrypt([ord(c) for c in plaintext], key)
    end_time = time.time()
    
    with open(output_file, 'w') as f:
        f.write(''.join(format(byte, '02x') for byte in ciphertext))
    
    print(f"Encryption time: {end_time - start_time} seconds")

def modify_bit(data, bit_position):
    byte_index = bit_position // 8
    bit_index = bit_position % 8
    modified_byte = data[byte_index] ^ (1 << bit_index)
    return data[:byte_index] + [modified_byte] + data[byte_index + 1:]

def calculate_avalanche_effect(plaintext, key, bit_position, modify_plaintext=True):
    original_ciphertext = encrypt([ord(c) for c in plaintext], key)
    if modify_plaintext:
        modified_plaintext = modify_bit([ord(c) for c in plaintext], bit_position)
        modified_ciphertext = encrypt(modified_plaintext, key)
    else:
        modified_key = modify_bit(key, bit_position)
        modified_ciphertext = encrypt([ord(c) for c in plaintext], modified_key)
    
    changed_bits = sum(b1 != b2 for b1, b2 in zip(original_ciphertext, modified_ciphertext))
    return changed_bits

def export_avalanche_effect_to_csv(filename, plaintext, key, bit_position, modify_plaintext=True):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Round', 'Changed Bits']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        original_ciphertext = encrypt([ord(c) for c in plaintext], key)
        for round in range(1, 11):
            if modify_plaintext:
                modified_plaintext = modify_bit([ord(c) for c in plaintext], bit_position)
                modified_ciphertext = encrypt(modified_plaintext, key)
            else:
                modified_key = modify_bit(key, bit_position)
                modified_ciphertext = encrypt([ord(c) for c in plaintext], modified_key)
            
            changed_bits = sum(b1 != b2 for b1, b2 in zip(original_ciphertext, modified_ciphertext))
            writer.writerow({'Round': round, 'Changed Bits': changed_bits})
