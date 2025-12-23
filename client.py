"""
This script acts as a client to a network anomaly detection server.
It loads pre-trained ML models, connects to a server to receive packet data,
preprocesses the data, and then uses the loaded model to predict if the packet is an anomaly.
"""

import socket
import json
import pandas as pd
import joblib

rf_model = joblib.load("rf_model.pkl")
encoder = joblib.load("encoder.pkl")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 12345))

packet_data = client.recv(4096).decode()
client.close()

dummy_packet = pd.DataFrame(json.loads(packet_data))

for col in scaler.feature_names_in_:
    if col not in dummy_packet.columns:
        dummy_packet[col] = 0

categorical_cols = list(encoder.feature_names_in_)
for col in categorical_cols:
    dummy_packet[col] = dummy_packet[col].astype(str)
    dummy_packet[col] = dummy_packet[col].apply(lambda x: x if x in encoder.categories_[categorical_cols.index(col)] else "Unknown")

dummy_packet[categorical_cols] = encoder.transform(dummy_packet[categorical_cols])

dummy_packet_scaled = scaler.transform(dummy_packet)

prediction = rf_model.predict(dummy_packet_scaled)
alert = label_encoder.inverse_transform(prediction)[0]

print(f"Anomaly Detected: {alert}")
