from scapy.all import IP, TCP, UDP, ICMP, Raw, send
from random import randint, choice
import time
from src.utils import log_alert

LOCAL_IP = "127.0.0.1"

def generate_syn_flood(target_ip: str = LOCAL_IP, target_port: int = 80, count: int = 100, delay: float = 0.01):
    """
    Generates a SYN flood attack on the specified target IP and port.
    Rate-limited to prevent actual disruption.
    """
    log_alert(f"Generating SYN flood on {target_ip}:{target_port} with {count} packets at {1/delay} pkt/s", level='WARNING')
    for _ in range(count):
        src_port = randint(1024, 65535)
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        send(ip_layer/tcp_layer, verbose=0)
        time.sleep(delay)
    log_alert(f"SYN flood generation complete.", level='INFO')

def generate_port_scan(target_ip: str = LOCAL_IP, port_range: tuple = (1, 1024), count_per_port: int = 1, delay: float = 0.01):
    """
    Generates a TCP SYN port scan on the specified target IP over a port range.
    Rate-limited.
    """
    log_alert(f"Generating port scan on {target_ip} for ports {port_range[0]}-{port_range[1]} at {1/delay} pkt/s", level='WARNING')
    for port in range(port_range[0], port_range[1] + 1):
        for _ in range(count_per_port):
            src_port = randint(1024, 65535)
            ip_layer = IP(dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=port, flags="S")
            send(ip_layer/tcp_layer, verbose=0)
            time.sleep(delay)
    log_alert(f"Port scan generation complete.", level='INFO')

def generate_high_entropy_payload(target_ip: str = LOCAL_IP, target_port: int = 1234, count: int = 50, delay: float = 0.05, payload_size: int = 100):
    """
    Generates packets with high-entropy (random) payloads to simulate malicious traffic.
    """
    log_alert(f"Generating high-entropy payload traffic on {target_ip}:{target_port} with {count} packets at {1/delay} pkt/s", level='WARNING')
    for _ in range(count):
        src_port = randint(1024, 65535)
        payload = ''.join(choice('0123456789abcdef') for i in range(payload_size))
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="PA")
        send(ip_layer/tcp_layer/Raw(load=payload.encode()), verbose=0)
        time.sleep(delay)
    log_alert(f"High-entropy payload traffic generation complete.", level='INFO')

def generate_custom_packet(target_ip: str = LOCAL_IP, protocol: str = "tcp", sport: int = 12345, dport: int = 80, flags: str = "S", payload: str = None, count: int = 1, delay: float = 0.1):
    """
    Generates a custom packet based on provided parameters.
    """
    log_alert(f"Generating custom {protocol} packet to {target_ip}:{dport} (count: {count})", level='INFO')
    for _ in range(count):
        ip_layer = IP(dst=target_ip)
        if protocol.lower() == "tcp":
            transport_layer = TCP(sport=sport, dport=dport, flags=flags)
        elif protocol.lower() == "udp":
            transport_layer = UDP(sport=sport, dport=dport)
        elif protocol.lower() == "icmp":
            transport_layer = ICMP()
        else:
            log_alert(f"Unsupported protocol for custom packet: {protocol}", level='ERROR')
            return
        
        if payload:
            send(ip_layer/transport_layer/Raw(load=payload.encode()), verbose=0)
        else:
            send(ip_layer/transport_layer, verbose=0)
        time.sleep(delay)
    log_alert(f"Custom packet generation complete.", level='INFO')

