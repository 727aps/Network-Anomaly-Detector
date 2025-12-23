import streamlit as st
import pandas as pd
import plotly.express as px
import asyncio
import multiprocessing
import yaml
import time
import numpy as np
from random import randint, choice

from src.utils import get_network_interfaces, setup_logging, log_alert
from src.traffic_gen import generate_syn_flood, generate_port_scan, generate_high_entropy_payload, LOCAL_IP

from main import run_backend

def load_config():
    with open("config/config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css("web/style.css")

if 'sniffing_active' not in st.session_state:
    st.session_state.sniffing_active = False
if 'anomaly_data' not in st.session_state:
    st.session_state.anomaly_data = pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size', 'anomaly_label', 'anomaly_score'])
if 'alert_feed' not in st.session_state:
    st.session_state.alert_feed = []
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()
if 'traffic_volume' not in st.session_state:
    st.session_state.traffic_volume = pd.DataFrame(columns=['time', 'volume', 'anomaly'])
if 'backend_process' not in st.session_state:
    st.session_state.backend_process = None
if 'packet_q_mp' not in st.session_state:
    st.session_state.packet_q_mp = multiprocessing.Queue()
if 'feature_q_mp' not in st.session_state:
    st.session_state.feature_q_mp = multiprocessing.Queue()
if 'anomaly_q_mp' not in st.session_state:
    st.session_state.anomaly_q_mp = multiprocessing.Queue()
if 'stop_event_mp' not in st.session_state:
    st.session_state.stop_event_mp = multiprocessing.Event()

st.set_page_config(layout="wide")
st.title("🌐 Network Traffic Anomaly Detection System")

st.sidebar.header("⚙️ Controls")

available_interfaces = get_network_interfaces()
if not available_interfaces:
    st.sidebar.warning("No active network interfaces found. Ensure Npcap/WinPcap is installed.")
    selected_interface = None
else:
    selected_interface = st.sidebar.selectbox(
        "Select Network Interface",
        available_interfaces,
        index=available_interfaces.index(config['network_interface']) if config['network_interface'] in available_interfaces else 0
    )

selected_model = st.sidebar.selectbox(
    "Select ML Model",
    config['ml_models']['available'],
    index=config['ml_models']['available'].index(config['ml_models']['active'])
)

anomaly_threshold = st.sidebar.slider(
    "Anomaly Score Threshold",
    min_value=0.0, max_value=1.0, value=config['anomaly_threshold'], step=0.05
)

col1, col2 = st.sidebar.columns(2)

with col1:
    if st.button("▶️ Start Sniffing", disabled=st.session_state.sniffing_active or not selected_interface):
        st.session_state.sniffing_active = True
        st.session_state.stop_event_mp.clear()
        
        st.session_state.backend_process = multiprocessing.Process(
            target=run_backend,
            args=(
                st.session_state.packet_q_mp,
                st.session_state.feature_q_mp,
                st.session_state.anomaly_q_mp,
                st.session_state.stop_event_mp,
                config,
                selected_interface,
                selected_model,
                anomaly_threshold
            )
        )
        st.session_state.backend_process.start()
        st.info(f"Starting sniffing on {selected_interface} with {selected_model} model...")

with col2:
    if st.button("⏹️ Stop Sniffing", disabled=not st.session_state.sniffing_active):
        st.session_state.sniffing_active = False
        if st.session_state.backend_process:
            st.session_state.stop_event_mp.set()
            st.session_state.backend_process.join()
            st.session_state.backend_process = None
        st.info("Stopping sniffing...")

st.sidebar.markdown("--- ")
st.sidebar.header("🧪 Test Traffic Generator")

target_ip_test = st.sidebar.text_input("Target IP (for tests)", value=LOCAL_IP)

if st.sidebar.button("💥 Generate SYN Flood"):
    log_alert("Simulating SYN Flood (check console for output)", level='WARNING')
    generate_syn_flood(target_ip=target_ip_test, count=10, delay=0.05)

if st.sidebar.button("🔍 Generate Port Scan"):
    log_alert("Simulating Port Scan (check console for output)", level='WARNING')
    generate_port_scan(target_ip=target_ip_test, port_range=(1000, 1005), count_per_port=1, delay=0.05)

if st.sidebar.button("👽 Generate High Entropy Traffic"):
    log_alert("Simulating High Entropy Traffic (check console for output)", level='WARNING')
    generate_high_entropy_payload(target_ip=target_ip_test, count=5, delay=0.1)

st.header("📈 Live Anomaly Dashboard")

st.subheader("Recent Packet/Flow Data")
packet_df_placeholder = st.empty()

st.subheader("Traffic Volume & Anomalies Over Time")
traffic_chart_placeholder = st.empty()

st.subheader("Real-time Alert Feed")
alert_feed_placeholder = st.empty()

while st.session_state.sniffing_active or not st.session_state.anomaly_q_mp.empty():
    if not st.session_state.anomaly_q_mp.empty():
        try:
            anomaly_event = st.session_state.anomaly_q_mp.get_nowait()
            
            new_df = pd.DataFrame([anomaly_event])
            st.session_state.anomaly_data = pd.concat([st.session_state.anomaly_data, new_df], ignore_index=True)
            st.session_state.anomaly_data = st.session_state.anomaly_data.tail(100)

            alert_message = f"[{time.strftime('%H:%M:%S')}] ALERT: {anomaly_event['anomaly_label']} from {anomaly_event['src_ip']} (Score: {anomaly_event['anomaly_score']:.2f})"
            st.session_state.alert_feed.append(alert_message)
            if len(st.session_state.alert_feed) > 10:
                st.session_state.alert_feed.pop(0)
            
            current_volume_data = {'time': anomaly_event['timestamp'], 'volume': anomaly_event['packet_size'], 'anomaly': anomaly_event['anomaly_label'] != 'Normal'}
            st.session_state.traffic_volume = pd.concat([st.session_state.traffic_volume, pd.DataFrame([current_volume_data])], ignore_index=True)
            st.session_state.traffic_volume = st.session_state.traffic_volume[st.session_state.traffic_volume['time'] > (time.time() - 60)]

        except Exception as e:
            log_alert(f"Error reading from anomaly queue: {e}", level='ERROR')

    packet_df_placeholder.dataframe(st.session_state.anomaly_data, use_container_width=True)

    if not st.session_state.traffic_volume.empty:
        fig = px.line(
            st.session_state.traffic_volume,
            x='time', y='volume', color='anomaly',
            title="Traffic Volume Over Time (Anomalies Highlighted)",
            labels={'time': 'Time', 'volume': 'Packet Size', 'anomaly': 'Anomaly'},
            color_discrete_map={True: 'red', False: 'green'}
        )
        traffic_chart_placeholder.plotly_chart(fig, use_container_width=True)

    alert_feed_placeholder.text_area("", value="\n".join(st.session_state.alert_feed[::-1]), height=200)
    
    time.sleep(0.1)
    st.rerun()

if not st.session_state.anomaly_data.empty:
    csv_export = st.session_state.anomaly_data.to_csv(index=False).encode('utf-8')
    st.sidebar.download_button(
        label="⬇️ Export Anomalies (CSV)",
        data=csv_export,
        file_name="anomaly_detections.csv",
        mime="text/csv",
    )

st.sidebar.markdown("--- ")
st.sidebar.info("System Status: " + ("Running" if st.session_state.sniffing_active else "Stopped"))