# Logging setup for the application

import logging
import os

def setup_logger():
    """Set up and return a logger instance."""
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)  # Ensure the logs folder exists
    log_file = os.path.join(log_folder, "app.log")

    # Configure the logger
    logger = logging.getLogger("DigitalSignatureApp")
    logger.setLevel(logging.INFO)

    # Create file handler to write logs to a file
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    # Create console handler to output logs to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Define log format
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
