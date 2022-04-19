import logging
import sys
import time
import os

TIMESTAMP = time.strftime("%d-%m-%Y-%H%M%S")
CURRENT_DIR = os.getcwd()
LOG_FILE = CURRENT_DIR + "/logs/logfile" + TIMESTAMP + ".log"

# Create directory logs in current dir if it does not already exist.
if not os.path.exists("logs"):
    try:
        os.makedirs("logs")
    except OSError as e:
        raise e

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set-up basic configuration. This needs to be set-up only once.
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Creating logger which will be used in other files.
file_handler = logging.FileHandler(LOG_FILE)
file_handler = logging.StreamHandler(sys.stdout)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
