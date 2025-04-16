import logging
import os

# Configure logging settings
LOG_FILE = 'application.log'

def setup_logging():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w'):
            pass
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def log_event(event_message):
    logging.info(event_message)

def log_error(error_message):
    logging.error(error_message)