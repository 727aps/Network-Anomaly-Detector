"""
This script implements a simple socket server that sends a dummy network packet
data in JSON format to a connected client. This is used for testing the client-side
anomaly detection.
"""
import socket
import json
import pandas as pd

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

packet_json = dummy_packet.to_json(orient="records")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 12345))
server.listen(1)

print("Server is waiting for a connection...")
conn, addr = server.accept()
print(f"Connected to {addr}")

conn.sendall(packet_json.encode())
print("Packet sent.")

conn.close()
server.close()
