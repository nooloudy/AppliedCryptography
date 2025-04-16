import unittest
from src.crypto.key_generation import generate_rsa_keypair, generate_dsa_keypair, generate_elgamal_keypair

class TestKeyGeneration(unittest.TestCase):

    def test_rsa_key_generation(self):
        private_key, public_key = generate_rsa_keypair(2048)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(len(private_key), 2048)
        self.assertEqual(len(public_key), 2048)

    def test_dsa_key_generation(self):
        private_key, public_key = generate_dsa_keypair(2048)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(len(private_key), 2048)
        self.assertEqual(len(public_key), 2048)

    def test_elgamal_key_generation(self):
        private_key, public_key = generate_elgamal_keypair(2048)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertEqual(len(private_key), 2048)
        self.assertEqual(len(public_key), 2048)

if __name__ == '__main__':
    unittest.main()