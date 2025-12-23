import socket
import json
import pandas as pd
import joblib

# Load the trained models
rf_model = joblib.load("rf_model.pkl")
encoder = joblib.load("encoder.pkl")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Create a socket client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 12345))  # Connect to the server

# Receive data
packet_data = client.recv(4096).decode()
client.close()

# Convert JSON data to DataFrame
dummy_packet = pd.DataFrame(json.loads(packet_data))

# Ensure all required columns exist
for col in scaler.feature_names_in_:
    if col not in dummy_packet.columns:
        dummy_packet[col] = 0  # Default value for missing columns

# Encode categorical features
categorical_cols = list(encoder.feature_names_in_)
for col in categorical_cols:
    dummy_packet[col] = dummy_packet[col].astype(str)
    dummy_packet[col] = dummy_packet[col].apply(lambda x: x if x in encoder.categories_[categorical_cols.index(col)] else "Unknown")

dummy_packet[categorical_cols] = encoder.transform(dummy_packet[categorical_cols])

# Scale numerical features
dummy_packet_scaled = scaler.transform(dummy_packet)

# Predict anomaly
prediction = rf_model.predict(dummy_packet_scaled)
alert = label_encoder.inverse_transform(prediction)[0]

print(f"Anomaly Detected: {alert}")
