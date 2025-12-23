import argparse
import asyncio
import yaml
import time
import pandas as pd
import multiprocessing

from src.sniffer import packet_sniffer
from src.features import extract_features
from src.ml_models import MLModelManager
from src.anomaly_detector import AnomalyDetector
from src.traffic_gen import generate_syn_flood, generate_port_scan, generate_high_entropy_payload, generate_custom_packet, LOCAL_IP
from src.utils import setup_logging, log_alert, get_network_interfaces


async def _async_queue_put(q_mp, item):
    q_mp.put(item)


async def feature_extraction_worker(packet_queue: multiprocessing.Queue, feature_queue: multiprocessing.Queue, stop_event: multiprocessing.Event):
    """
    Worker to extract features from raw packets and put them into the feature queue.
    """
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=0.1) 
            features = extract_features(packet)
            await _async_queue_put(feature_queue, features)
        except multiprocessing.queues.Empty:
            await asyncio.sleep(0.01) # Small sleep to prevent busy-waiting
        except Exception as e:
            log_alert(f"Error in feature extraction worker: {e}", level='ERROR')

async def anomaly_detection_worker(feature_queue: multiprocessing.Queue, anomaly_queue: multiprocessing.Queue, detector: AnomalyDetector, stop_event: multiprocessing.Event):
    """
    Worker to take features, run anomaly detection, and put results into the anomaly queue.
    """
    batch_features = []
    batch_start_time = time.time()
    BATCH_WINDOW = 5

    while not stop_event.is_set():
        try:
            batch_features.append(features)

            if (time.time() - batch_start_time) >= BATCH_WINDOW and batch_features:
                for feature_set in batch_features:
                    label, score = detector.detect(feature_set)
                    if label != "Normal":
                        await _async_queue_put(anomaly_queue, {
                            "timestamp": time.time(),
                            "src_ip": feature_set.get('src_ip'),
                            "dst_ip": feature_set.get('dst_ip'),
                            "protocol": feature_set.get('proto'),
                            "packet_size": feature_set.get('packet_size'),
                            "anomaly_label": label,
                            "anomaly_score": score
                        })
                batch_features = []
                batch_start_time = time.time()

        except multiprocessing.queues.Empty:
            await asyncio.sleep(0.01) # Small sleep to prevent busy-waiting
        except Exception as e:
            log_alert(f"Error in anomaly detection worker: {e}", level='ERROR')

async def _async_packet_sniffer_wrapper(packet_queue_mp, interface, bpf_filter):
    packet_queue_async = asyncio.Queue()
    sniffer_task = asyncio.create_task(packet_sniffer(packet_queue_async, interface=interface, bpf_filter=bpf_filter))

    while not STOP_SNIFFING.is_set():
        try:
            packet = await asyncio.wait_for(packet_queue_async.get(), timeout=0.1)
            packet_queue_mp.put(packet)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log_alert(f"Error in async packet sniffer wrapper: {e}", level='ERROR')
    sniffer_task.cancel()
    try:
        await sniffer_task
    except asyncio.CancelledError:
        log_alert("Sniffer task cancelled.", level='INFO')


def run_backend(packet_q_mp: multiprocessing.Queue, feature_q_mp: multiprocessing.Queue, anomaly_q_mp: multiprocessing.Queue, stop_event_mp: multiprocessing.Event, config: dict, selected_interface: str, selected_model: str, anomaly_threshold: float):
    """
    Main function to run the backend sniffing and anomaly detection processes.
    """
    setup_logging(log_level=config['logging']['level'], log_file=config['logging']['file'])
    log_alert("Backend process started.", level='INFO')

    global STOP_SNIFFING
    STOP_SNIFFING = stop_event_mp

    ml_model_manager = MLModelManager(models_dir="data/models")
    ml_model_manager = MLModelManager(models_dir="data/models")

    if not ml_model_manager.load_model(selected_model):
        log_alert(f"Failed to load ML model: {selected_model}. Exiting backend.", level='ERROR')
        return
    
    anomaly_detector = AnomalyDetector(ml_model_manager, threshold=anomaly_threshold)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    sniffer_task = loop.create_task(_async_packet_sniffer_wrapper(packet_q_mp, interface=selected_interface, bpf_filter=None))
    feature_task = loop.create_task(feature_extraction_worker(packet_q_mp, feature_q_mp, stop_event_mp))
    detection_task = loop.create_task(anomaly_detection_worker(feature_q_mp, anomaly_q_mp, anomaly_detector, stop_event_mp))

    try:
        loop.run_until_complete(asyncio.gather(sniffer_task, feature_task, detection_task, return_exceptions=True))
    except KeyboardInterrupt:
        log_alert("Backend caught KeyboardInterrupt, stopping.", level='INFO')
    finally:
        stop_event_mp.set()
        for task in asyncio.all_tasks(loop):
            task.cancel()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        log_alert("Backend process stopped.", level='INFO')


async def main_cli():
    parser = argparse.ArgumentParser(description="Network Traffic Anomaly Detection System")
    parser.add_argument("--mode", type=str, choices=['live', 'test'], required=True, help="Operation mode: 'live' for sniffing, 'test' for traffic generation.")
    parser.add_argument("--interface", type=str, help="Network interface to sniff on (e.g., eth0, Wi-Fi). Use 'auto' to auto-detect.")
    parser.add_argument("--model", type=str, default="IsolationForest", choices=['IsolationForest', 'LSTM'], help="ML model to use for anomaly detection.")
    parser.add_argument("--threshold", type=float, default=0.7, help="Anomaly score threshold for detection.")
    parser.add_argument("--log-level", type=str, default="INFO", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="Logging level.")

    parser.add_argument("--attack", type=str, choices=['syn_flood', 'port_scan', 'high_entropy', 'custom'], help="Type of attack to simulate in test mode.")
    parser.add_argument("--target-ip", type=str, default=LOCAL_IP, help="Target IP for simulated attacks.")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to send in test mode.")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets in test mode.")
    parser.add_argument("--target-port", type=int, default=80, help="Target port for syn_flood or high_entropy attack.")
    parser.add_argument("--port-range-start", type=int, default=1, help="Start of port range for port_scan.")
    parser.add_argument("--port-range-end", type=int, default=1024, help="End of port range for port_scan.")
    parser.add_argument("--payload-size", type=int, default=100, help="Size of payload for high_entropy attack.")


    args = parser.parse_args()
    setup_logging(log_level=args.log_level, log_file='system.log')

    if args.mode == 'test':
        log_alert(f"Starting traffic generation in test mode: {args.attack}", level='INFO')
        if args.attack == 'syn_flood':
            generate_syn_flood(target_ip=args.target_ip, target_port=args.target_port, count=args.count, delay=args.delay)
        elif args.attack == 'port_scan':
            generate_port_scan(target_ip=args.target_ip, port_range=(args.port_range_start, args.port_range_end), count_per_port=args.count, delay=args.delay)
        elif args.attack == 'high_entropy':
            generate_high_entropy_payload(target_ip=args.target_ip, target_port=args.target_port, count=args.count, delay=args.delay, payload_size=args.payload_size)
        elif args.attack == 'custom':
            log_alert("Custom packet generation requires more specific parameters. Please modify code directly for now.", level='WARNING')
        else:
            log_alert("Invalid attack type specified for test mode.", level='ERROR')
    
    elif args.mode == 'live':
        log_alert("Starting live anomaly detection system...", level='INFO')

        selected_interface = args.interface
        if not selected_interface or selected_interface.lower() == 'auto':
            interfaces = get_network_interfaces()
            if not interfaces:
                log_alert("No active network interfaces found. Please specify an interface manually or ensure WinPcap/Npcap is installed.", level='ERROR')
                return
            selected_interface = interfaces[0]
            log_alert(f"Auto-detecting interface. Using: {selected_interface}", level='INFO')

        packet_q_mp = multiprocessing.Queue()
        feature_q_mp = multiprocessing.Queue()
        anomaly_q_mp = multiprocessing.Queue()
        stop_event_mp = multiprocessing.Event()
        
        with open("config/config.yaml", "r") as f:
            cfg = yaml.safe_load(f)

        backend_process = multiprocessing.Process(
            target=run_backend,
            args=(packet_q_mp, feature_q_mp, anomaly_q_mp, stop_event_mp, cfg, selected_interface, args.model, args.threshold)
        )
        backend_process.start()

        try:
            while True:
                if not anomaly_q_mp.empty():
                    anomaly_event = anomaly_q_mp.get()
                    log_alert(f"Detected Anomaly: {anomaly_event['anomaly_label']} with score {anomaly_event['anomaly_score']:.2f} from {anomaly_event['src_ip']}", level='WARNING')
                await asyncio.sleep(0.1)
        except KeyboardInterrupt:
            log_alert("Stopping anomaly detection system.", level='INFO')
        finally:
            backend_process.join()
            log_alert("System stopped.", level='INFO')

if __name__ == "__main__":
    multiprocessing.freeze_support()
    asyncio.run(main_cli())
