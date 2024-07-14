import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier

# Load model trained on NSL-KDD dataset
clf = RandomForestClassifier(n_estimators=100, random_state=42)
# Load your pre-trained model here

def detect_ddos(packet, detected_attacks, log_message, send_telegram_message):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        protocol = packet[IP].proto
        length = len(packet)
        
        packet_df = pd.DataFrame([[length, protocol]], columns=['length', 'protocol'])
        
        prediction = clf.predict(packet_df)

        if prediction == 'neptune':
            detected_attack = {
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Attack Type": "DDoS",
                "Source IP": src_ip
            }
            detected_attacks.append(detected_attack)
            message = f"Detected DDoS Attack from IP: {src_ip}"
            log_message(message)
            send_telegram_message(message)
