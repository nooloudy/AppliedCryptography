# filepath: /c:/Users/User/Desktop/AppliedCryptography/task6/rsa-gui-app/src/utils/logger.py

import logging

# Configure logging
logging.basicConfig(
    filename="operations.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_operation(message):
    """Logs an operation to the operations.log file."""
    logging.info(message)