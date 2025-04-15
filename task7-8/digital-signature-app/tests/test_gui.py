import unittest
from src.gui.main_window import MainWindow

class TestMainWindow(unittest.TestCase):

    def setUp(self):
        self.window = MainWindow()

    def test_algorithm_selection(self):
        algorithms = self.window.get_algorithm_options()
        self.assertIn('RSA', algorithms)
        self.assertIn('ElGamal', algorithms)
        self.assertIn('DSA', algorithms)

    def test_hashing_algorithm_selection(self):
        hashing_algorithms = self.window.get_hashing_algorithm_options()
        self.assertIn('SHA-256', hashing_algorithms)
        self.assertIn('SHA-384', hashing_algorithms)
        self.assertIn('SHA-512', hashing_algorithms)

    def test_key_generation(self):
        self.window.select_algorithm('RSA')
        self.window.generate_keys()
        public_key, private_key = self.window.get_generated_keys()
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)

    def test_signature_creation(self):
        self.window.select_algorithm('RSA')
        self.window.generate_keys()
        self.window.set_message("Test message")
        self.window.select_hashing_algorithm('SHA-256')
        signature = self.window.create_signature()
        self.assertIsNotNone(signature)

    def test_signature_verification(self):
        self.window.select_algorithm('RSA')
        self.window.generate_keys()
        self.window.set_message("Test message")
        self.window.select_hashing_algorithm('SHA-256')
        signature = self.window.create_signature()
        verification_result = self.window.verify_signature(signature)
        self.assertTrue(verification_result)

if __name__ == '__main__':
    unittest.main()