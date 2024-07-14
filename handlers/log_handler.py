import logging
import os

def setup_logging(log_folder):
    os.makedirs(log_folder, exist_ok=True)
    logging.basicConfig(
        filename=os.path.join(log_folder, "attack_log.log"),
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

def log_message(message):
    logging.info(message)
