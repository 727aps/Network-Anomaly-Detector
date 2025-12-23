# Network Traffic Anomaly Detection System

A real-time, ML-powered system for detecting anomalies in network traffic, featuring live packet sniffing, comprehensive feature extraction, multi-model anomaly detection, and a professional web-based dashboard.

## Architecture

```mermaid
graph TD
    User --> WebUI[Web UI (Streamlit)]
    WebUI --> Config[Configuration]
    Sniffer[Live Traffic Sniffer] --> PacketQueue[Packet Queue]
    TrafficGen[Anomalous Traffic Generator] --> PacketQueue

    PacketQueue --> FeatureExtractor[Feature Extractor]
    FeatureExtractor --> FlowAggregator[Flow Aggregator]
    FlowAggregator --> FeatureQueue[Feature Queue]

    FeatureQueue --> MLModels[ML Models (LSTM, Isolation Forest, Rules)]
    MLModels --> AnomalyDetector[Anomaly Detector]

    AnomalyDetector --> WebUI
    AnomalyDetector --> Logger[Logger/Alerter]
    Logger --> Outputs[Outputs (CSV, Plots, Console)]

    OfflineTrain[Offline Training Notebook] --> MLModels
```

## Features

1.  **Live Traffic Sniffing:** Captures network packets from selected network interfaces (e.g., Wi-Fi, Ethernet) using `scapy` and `psutil`.
2.  **Anomalous Traffic Generation:** Safely simulates various network attacks (SYN floods, port scans, high-entropy payloads) on `localhost` for testing and demonstration.
3.  **Multiple ML Models:** Integrates rule-based logic with advanced machine learning models like Isolation Forest and LSTM for robust anomaly detection. Supports dynamic switching via configuration.
4.  **Real-time Inference:** Processes buffered packets in asynchronous queues, extracts flow-based features, and performs real-time anomaly prediction.
5.  **Professional Web UI:** A responsive Streamlit dashboard providing:
    *   Sidebar controls for sniffing, model selection, threshold adjustment, and test traffic generation.
    *   Live packet/flow data table.
    *   Anomaly heatmap/line chart (Plotly) for visualizing traffic volume and alerts.
    *   Real-time anomaly alert feed.
6.  **Clear Outputs & Logs:** Produces structured logs to console and file, CSV exports of detections, and visualizes anomalies.
7.  **Jupyter Notebook Integration:** Includes an offline notebook for model training visualization, synthetic data simulation, and comprehensive model evaluation (ROC-AUC, Precision-Recall).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd network-traffic-anomaly-detection-system
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows:
    # .\venv\Scripts\activate
    # On macOS/Linux:
    # source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Npcap (Windows) or configure libpcap (Linux/macOS) for Scapy:**
    *   **Windows:** Download and install [Npcap](https://nmap.org/npcap/).
    *   **Linux/macOS:** Ensure `libpcap-dev` (or equivalent) is installed (e.g., `sudo apt-get install libpcap-dev` on Debian/Ubuntu, `brew install libpcap` on macOS).

5.  **Train and save initial ML models:**
    Run the Jupyter notebook to train and save the `IsolationForest` and `LSTM` models along with their preprocessors. This will populate the `data/models/` directory.
    ```bash
    jupyter notebook notebooks/demo_anomaly_detection.ipynb
    # Run all cells in the notebook.
    ```

## Usage

### Command-Line Interface (CLI) Mode

Run the `main.py` script for live sniffing or traffic generation.

*   **Live Anomaly Detection:**
    ```bash
    python main.py --mode live --interface <your_network_interface> --model IsolationForest --threshold 0.7
    # Example (Windows): python main.py --mode live --interface "Wi-Fi" --model LSTM
    # Example (Linux): python main.py --mode live --interface "eth0" --model IsolationForest
    ```
    Use `--interface auto` to auto-detect the network interface.

*   **Generate Test Traffic:**
    ```bash
    python main.py --mode test --attack syn_flood --target-ip 127.0.0.1 --count 50 --delay 0.05
    python main.py --mode test --attack port_scan --target-ip 127.0.0.1 --port-range-start 1000 --port-range-end 1010
    python main.py --mode test --attack high_entropy --target-ip 127.0.0.1 --count 20
    ```

### Web UI Mode (Streamlit)

Run the Streamlit application for an interactive dashboard.

```bash
streamlit run web/app.py
```
Access the application at `http://localhost:8501` (or the port displayed in your terminal).

### Notebook Mode

Open and run the Jupyter notebook for offline model development and analysis.

```bash
jupyter notebook notebooks/demo_anomaly_detection.ipynb
```

## Screenshots

*(Screenshots of the Streamlit dashboard and notebook outputs will be added here.)*

## Outputs

*   **Console/Logs:** Real-time anomaly alerts and system status messages are printed to the console and saved to `system.log`.
*   **CSV Exports:** The Streamlit UI allows downloading detected anomalies as a CSV file.
*   **Plots:** Offline plots from the Jupyter notebook (e.g., confusion matrices, feature importance) can be saved as PNG images.

