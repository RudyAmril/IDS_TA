import os
import time
import threading
from scapy.all import sniff
from configparser import ConfigParser
from handlers.telegram_handler import send_telegram_message
from handlers.log_handler import setup_logging, log_message
from detectors.ddos_detector import detect_ddos
from detectors.brute_force_detector import detect_brute_force
from utils.preprocess import preprocess_data

# Baca konfigurasi
config = ConfigParser()
config.read('config/config.json')
TELEGRAM_TOKEN = config['telegram']['token']
TELEGRAM_CHAT_ID = config['telegram']['chat_id']
LOG_FOLDER = config['log']['folder']
INTERFACE = config['network']['interface']

# Setup logging
setup_logging(LOG_FOLDER)

# Global variables
detected_attacks = []

def packet_callback(packet):
    detect_ddos(packet, detected_attacks, log_message, send_telegram_message)
    detect_brute_force(packet, detected_attacks, log_message, send_telegram_message)

def print_detected_attacks():
    while True:
        if detected_attacks:
            for attack in detected_attacks:
                print(f"{attack['Timestamp']} - {attack['Attack Type']} from {attack['Source IP']}")
            detected_attacks.clear()
        time.sleep(10)

def print_no_attacks():
    while True:
        if not detected_attacks:
            print("No attacks detected.")
        time.sleep(15)

def send_latest_log_to_telegram():
    while True:
        with open(os.path.join(LOG_FOLDER, "attack_log.log"), "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1]
                send_telegram_message(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, last_line.strip())
        time.sleep(60)

if __name__ == "__main__":
    print_thread = threading.Thread(target=print_detected_attacks)
    no_attacks_thread = threading.Thread(target=print_no_attacks)
    log_thread = threading.Thread(target=send_latest_log_to_telegram)

    print_thread.start()
    no_attacks_thread.start()
    log_thread.start()

    print(f"Starting packet capture on interface {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_callback, store=0)
