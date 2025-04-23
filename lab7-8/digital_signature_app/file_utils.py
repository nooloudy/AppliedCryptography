# File utilities for saving/loading keys and signatures

import os
import time
import json

# Create directories for storing keys, messages, and signatures
os.makedirs("public_keys", exist_ok=True)
os.makedirs("private_keys", exist_ok=True)
os.makedirs("messages", exist_ok=True)
os.makedirs("signatures", exist_ok=True)

def get_timestamp():
    """Return the current timestamp as a string."""
    return time.strftime("%Y%m%d_%H%M%S")

def save_to_file(data, folder, filename):
    """Save data to a file in the specified folder."""
    filepath = os.path.join(folder, filename)
    with open(filepath, "w") as file:
        if isinstance(data, (dict, list)):
            json.dump(data, file)  # Save as JSON if data is a dictionary or list
        else:
            file.write(str(data))  # Save as plain text otherwise
    return filepath

def load_from_file(filepath):
    """Load data from a file."""
    with open(filepath, "r") as file:
        try:
            return json.load(file)  # Try to load as JSON
        except json.JSONDecodeError:
            return file.read()  # Fallback to plain text

def save_public_key(algorithm, public_key):
    """Save the public key to the public_keys folder."""
    timestamp = get_timestamp()
    filename = f"{algorithm}_public_key_{timestamp}.txt"
    return save_to_file(public_key, "public_keys", filename)

def save_private_key(algorithm, private_key):
    """Save the private key to the private_keys folder."""
    timestamp = get_timestamp()
    filename = f"{algorithm}_private_key_{timestamp}.txt"
    return save_to_file(private_key, "private_keys", filename)

def save_message(algorithm, message):
    """Save the message to the messages folder."""
    timestamp = get_timestamp()
    filename = f"{algorithm}_message_{timestamp}.txt"
    return save_to_file(message, "messages", filename)

def save_signature(algorithm, signature):
    """Save the signature to the signatures folder."""
    timestamp = get_timestamp()
    filename = f"{algorithm}_signature_{timestamp}.txt"
    return save_to_file(signature, "signatures", filename)
