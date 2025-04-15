import unittest
from src.algorithms.rsa import RSA
from src.algorithms.elgamal import ElGamal
from src.algorithms.dsa import DSA
from src.hashing.sha256 import SHA256
from src.hashing.sha384 import SHA384
from src.hashing.sha512 import SHA512

class TestAlgorithms(unittest.TestCase):

    def setUp(self):
        self.rsa = RSA()
        self.elgamal = ElGamal()
        self.dsa = DSA()
        self.message = "Test message"
        self.rsa_key_pair = self.rsa.generate_keys()
        self.elgamal_key_pair = self.elgamal.generate_keys()
        self.dsa_key_pair = self.dsa.generate_keys()

    def test_rsa_signature_verification(self):
        hashed_message = SHA256.hash(self.message)
        signature = self.rsa.sign(hashed_message, self.rsa_key_pair['private'])
        verification = self.rsa.verify(hashed_message, signature, self.rsa_key_pair['public'])
        self.assertTrue(verification)

    def test_elgamal_signature_verification(self):
        hashed_message = SHA256.hash(self.message)
        signature = self.elgamal.sign(hashed_message, self.elgamal_key_pair['private'])
        verification = self.elgamal.verify(hashed_message, signature, self.elgamal_key_pair['public'])
        self.assertTrue(verification)

    def test_dsa_signature_verification(self):
        hashed_message = SHA256.hash(self.message)
        signature = self.dsa.sign(hashed_message, self.dsa_key_pair['private'])
        verification = self.dsa.verify(hashed_message, signature, self.dsa_key_pair['public'])
        self.assertTrue(verification)

    def test_invalid_signature(self):
        hashed_message = SHA256.hash(self.message)
        invalid_signature = "invalid_signature"
        verification_rsa = self.rsa.verify(hashed_message, invalid_signature, self.rsa_key_pair['public'])
        verification_elgamal = self.elgamal.verify(hashed_message, invalid_signature, self.elgamal_key_pair['public'])
        verification_dsa = self.dsa.verify(hashed_message, invalid_signature, self.dsa_key_pair['public'])
        self.assertFalse(verification_rsa)
        self.assertFalse(verification_elgamal)
        self.assertFalse(verification_dsa)

if __name__ == '__main__':
    unittest.main()