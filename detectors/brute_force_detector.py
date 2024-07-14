import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier

# Load model trained on NSL-KDD dataset
clf = RandomForestClassifier(n_estimators=100, random_state=42)
# Load your pre-trained model here

def detect_brute_force(packet, detected_attacks, log_message, send_telegram_message):
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        
        packet_df = pd.DataFrame([[len(packet), packet[IP].proto]], columns=['length', 'protocol'])
        
        prediction = clf.predict(packet_df)

        if prediction == 'guess_passwd':
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "Brute Force",
                "Source IP": src_ip
            }
            detected_attacks.append(detected_attack)
            message = f"Detected Brute Force Attack from IP: {src_ip}"
            log_message(message)
            send_telegram_message(message)
