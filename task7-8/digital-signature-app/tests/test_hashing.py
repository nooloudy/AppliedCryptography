import unittest
from src.hashing.sha256 import hash_message as hash_sha256
from src.hashing.sha384 import hash_message as hash_sha384
from src.hashing.sha512 import hash_message as hash_sha512

class TestHashing(unittest.TestCase):

    def test_sha256(self):
        message = "Hello, World!"
        expected_hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda190f4b242c6c3d4e834"
        self.assertEqual(hash_sha256(message), expected_hash)

    def test_sha384(self):
        message = "Hello, World!"
        expected_hash = "ca737c3e1f8e3e7c1e4c5c9c7c3d4e834f0b2e4c5c9c7c3d4e834f0b2e4c5c9c"
        self.assertEqual(hash_sha384(message), expected_hash)

    def test_sha512(self):
        message = "Hello, World!"
        expected_hash = "861844d6704e8573fec34d967e20bcfe8b11b1f1e4c5c9c7c3d4e834f0b2e4c5c9c7c3d4e834f0b2e4c5c9c"
        self.assertEqual(hash_sha512(message), expected_hash)

if __name__ == '__main__':
    unittest.main()