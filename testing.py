import pandas as pd
import joblib

rf_model = joblib.load("rf_model.pkl")
encoder = joblib.load("encoder.pkl")
scaler = joblib.load("scaler.pkl")
label_encoder = joblib.load("label_encoder.pkl")

dummy_packet = pd.DataFrame([{
    "FLOW_ID": 368604472,
    "PROTOCOL_MAP": "tcp",
    "L4_SRC_PORT": 37914,
    "IPV4_SRC_ADDR": "10.114.241.166",
    "L4_DST_PORT": 38303,
    "IPV4_DST_ADDR": "10.114.224.218",
    "FIRST_SWITCHED": 1647686725,
    "FLOW_DURATION_MILLISECONDS": 1,
    "LAST_SWITCHED": 1647686725,
    "PROTOCOL": 6,
    "TCP_FLAGS": 22,
    "TCP_WIN_MAX_IN": 1024,
    "TCP_WIN_MAX_OUT": 0,
    "TCP_WIN_MIN_IN": 1024,
    "TCP_WIN_MIN_OUT": 0,
    "TCP_WIN_MSS_IN": 1460,
    "TCP_WIN_SCALE_IN": 0,
    "TCP_WIN_SCALE_OUT": 0,
    "SRC_TOS": 0,
    "DST_TOS": 0,
    "TOTAL_FLOWS_EXP": 368604472,
    "MIN_IP_PKT_LEN": 0,
    "MAX_IP_PKT_LEN": 0,
    "TOTAL_PKTS_EXP": 0,
    "TOTAL_BYTES_EXP": 0,
    "IN_BYTES": 44,
    "IN_PKTS": 1,
    "OUT_BYTES": 40,
    "OUT_PKTS": 1,
    "ANALYSIS_TIMESTAMP": 1647687338
}])

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

print(f" Anomaly Detected: {alert}")
