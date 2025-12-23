from sklearn.ensemble import IsolationForest
import pandas as pd


def classify_anomaly(packet_features):
    data = pd.DataFrame({
        'packet_size': [100, 200, 150, 300, 250, 500, 1200, 1500], 
        'src_ip': ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4', '192.168.0.5', '192.168.0.6', '192.168.0.7', '192.168.0.1'],  
        'dst_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5', '192.168.1.6', '192.168.1.7', '192.168.1.1'],  
        'protocol': ['TCP', 'UDP', 'TCP', 'ICMP', 'TCP', 'TCP', 'UDP', 'TCP'],  
        'payload': ['SELECT * FROM users', 'GET /home HTTP/1.1', 'DROP TABLE students', 'PING 192.168.0.1', 'UNION SELECT id, name FROM users', '', '', ''] 
    })
    
    
    
    numeric_data = data[['packet_size']]
    
    
    model = IsolationForest(contamination=0.1)
    model.fit(numeric_data)
    
    
    anomalies = model.predict(numeric_data)
    
    
    
    for i, packet in data.iterrows():
        print(f"\nProcessing packet {i+1}:")
        if anomalies[i] == -1:
           
            print(f"Anomaly detected in packet {i+1}:")
            if packet['packet_size'] > 250:
                print("DDoS Attack")
            if packet['src_ip'].count(packet['src_ip']) > 3:
                print("Port Scanning")
            if packet['protocol'] != 'TCP':  # Adjusted for protocol comparison
                print("Intrusion Detected")
            if packet['packet_size'] > 200:
                print("Malicious Traffic")
            payload = packet['payload'].lower()
            sql_keywords = ['union select', 'drop table', 'select *', '--', 'insert into']
            if any(keyword in payload for keyword in sql_keywords):
                print("SQL Injection Attempt")
            print(f"Anomaly detected in packet {i+1}: {packet['packet_size']} bytes")
        else:
            print(f"Packet {i+1} is normal.")
    
