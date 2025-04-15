def save_to_file(filename, data):
    with open(filename, 'w') as file:
        file.write(data)

def load_from_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def save_binary_to_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

def load_binary_from_file(filename):
    with open(filename, 'rb') as file:
        return file.read()