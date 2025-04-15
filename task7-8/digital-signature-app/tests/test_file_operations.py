import unittest
from src.utils.file_operations import save_to_file, load_from_file

class TestFileOperations(unittest.TestCase):

    def test_save_to_file(self):
        data = "Test data"
        filename = "test_file.txt"
        save_to_file(filename, data)
        
        with open(filename, 'r') as file:
            content = file.read()
        
        self.assertEqual(content, data)

    def test_load_from_file(self):
        data = "Test data"
        filename = "test_file.txt"
        save_to_file(filename, data)
        
        loaded_data = load_from_file(filename)
        self.assertEqual(loaded_data, data)

    def test_load_non_existent_file(self):
        with self.assertRaises(FileNotFoundError):
            load_from_file("non_existent_file.txt")

    def tearDown(self):
        import os
        try:
            os.remove("test_file.txt")
        except FileNotFoundError:
            pass

if __name__ == '__main__':
    unittest.main()