import unittest
from src.crypto.signing import create_signature
from src.crypto.key_generation import generate_keys
from src.crypto.verification import verify_signature

class TestSigning(unittest.TestCase):

    def setUp(self):
        self.algorithm = 'RSA'
        self.message = 'Test message for signing'
        self.private_key, self.public_key = generate_keys(self.algorithm)

    def test_signature_creation(self):
        signature = create_signature(self.message, self.private_key, self.algorithm)
        self.assertIsNotNone(signature)

    def test_signature_verification(self):
        signature = create_signature(self.message, self.private_key, self.algorithm)
        is_valid = verify_signature(self.message, signature, self.public_key, self.algorithm)
        self.assertTrue(is_valid)

    def test_invalid_signature_verification(self):
        invalid_signature = 'invalid_signature'
        is_valid = verify_signature(self.message, invalid_signature, self.public_key, self.algorithm)
        self.assertFalse(is_valid)

if __name__ == '__main__':
    unittest.main()