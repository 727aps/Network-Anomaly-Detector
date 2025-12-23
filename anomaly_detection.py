from sklearn.ensemble import IsolationForest
import pandas as pd

# Example of feature extraction from network packets (you will use your own packet data)
def classify_anomaly(packet_features):
    # Define the features (this can be expanded based on actual packet features)
    data = pd.DataFrame([{
        'packet_size': packet_features['packet_size'],
        'protocol': packet_features['protocol']
    }])
   
    # Create and train the Isolation Forest model
    model = IsolationForest(contamination=0.1)  # 10% of data are anomalies, adjust as necessary
    model.fit(data)
    
    # Use the trained model to detect anomalies
    anomaly = model.predict(data)  # 1 for normal, -1 for anomaly
    # Rule-based anomaly classification
    if anomaly == -1:
        # DDoS: High packet size
        if packet_features['packet_size'] > 250:
            #print("DDoS Attack")
            return 'DDoS Attack'
        # Port Scanning: Multiple different ports accessed by same source IP
        if packet_features['src_ip'].count(packet_features['src_ip']) > 3:
            #print("Port Scanning")
            return 'Port Scanning'
        # Intrusion: Unexpected protocol (non-TCP, e.g., ICMP or UDP)
        if packet_features['protocol'] != 6:  # 6 for TCP
            #print("Intrusion Detected")
            return 'Intrusion Detected'
        # Malicious Traffic: Unusually large packets
        if packet_features['packet_size'] > 200:
            #print("Malicious Traffic")
            return 'Malicious Traffic'
        # SQL Injection: Suspicious SQL-related strings in the payload
        payload = packet_features['payload'].lower()
        sql_keywords = ['union select', 'drop table', 'select *', '--', 'insert into']
        if any(keyword in payload for keyword in sql_keywords):
            #print("SQL Injection Attempt")
            return 'SQL Injection Attempt'
        return 'Unidentified Anomaly'
    #print("Normal")
    return 'Normal'
