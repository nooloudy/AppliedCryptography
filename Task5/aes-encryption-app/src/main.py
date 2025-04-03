from aes import encrypt_file, calculate_avalanche_effect, export_avalanche_effect_to_csv
from file_utils import read_key_file, read_plaintext_file, write_file, bytes_to_hex

def main():
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x9f, 0x24, 0x30, 0xc0, 0x4d]
    plaintext = "Nurlybek"
    bit_position = 5

    write_file('key.txt', bytes_to_hex(bytes(key)))
    write_file('plaintext.txt', plaintext)

    encrypt_file('plaintext.txt', 'ciphertext.txt', key)

    changed_bits = calculate_avalanche_effect(plaintext, key, bit_position, modify_plaintext=True)
    print(f"Number of changed bits in ciphertext: {changed_bits}")

    export_avalanche_effect_to_csv('avalanche_effect.csv', plaintext, key, bit_position, modify_plaintext=True)

if __name__ == "__main__":
    main()