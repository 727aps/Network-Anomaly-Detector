from sklearn.ensemble import IsolationForest
import pandas as pd

def classify_anomaly(packet_features):
    """
    Classifies network packet features as anomalous or normal using Isolation Forest and rule-based checks.
    """
    data = pd.DataFrame([{
        'packet_size': packet_features['packet_size'],
        'protocol': packet_features['protocol']
    }])
   
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    
    anomaly = model.predict(data)
    if anomaly == -1:
        if packet_features['packet_size'] > 250:
            return 'DDoS Attack'
        if packet_features['src_ip'].count(packet_features['src_ip']) > 3:
            return 'Port Scanning'
        if packet_features['protocol'] != 6:  # 6 for TCP
            return 'Intrusion Detected'
        if packet_features['packet_size'] > 200:
            return 'Malicious Traffic'
        payload = packet_features['payload'].lower()
        sql_keywords = ['union select', 'drop table', 'select *', '--', 'insert into']
        if any(keyword in payload for keyword in sql_keywords):
            return 'SQL Injection Attempt'
        return 'Unidentified Anomaly'
    return 'Normal'
