import pandas as pd
import numpy as np
from scapy.all import Packet, IP, TCP, UDP, ICMP
import time
from collections import defaultdict, deque

FLOW_TABLE = {}
FLOW_TIMEOUT = 10

LAST_N_CONNECTIONS = deque(maxlen=100)

def _get_flow_key(packet, reverse=False):
    """
    Generates a unique flow key for a given packet (5-tuple).
    If reverse is True, generates the key with source and destination swapped.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if reverse:
            return f"{dst_ip}-{dst_port}-{src_ip}-{src_port}-{proto}"
        else:
            return f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{proto}"
    return None

def _get_service(packet):
    """
    Determines the service based on common port numbers.
    """
    if TCP in packet:
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport == 80 or sport == 80: return "http"
        if dport == 443 or sport == 443: return "https"
        if dport == 21 or sport == 21: return "ftp"
        if dport == 22 or sport == 22: return "ssh"
        if dport == 23 or sport == 23: return "telnet"
        if dport == 25 or sport == 25: return "smtp"
        if dport == 53 or sport == 53: return "dns"
    elif UDP in packet:
        dport = packet[UDP].dport
        sport = packet[UDP].sport
        if dport == 53 or sport == 53: return "dns"
    return "-"

def _update_flow_table(packet):
    """
    Updates the global flow table with packet information for flow aggregation
    and updates LAST_N_CONNECTIONS for 'ct_' features.
    """
    flow_key = _get_flow_key(packet)
    if not flow_key:
        return

    current_time = time.time()
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    service = _get_service(packet)
    state = 'INT'

    src_port, dst_port = 0, 0
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if packet[TCP].flags.S and not packet[TCP].flags.A: state = 'SYN'
        elif packet[TCP].flags.S and packet[TCP].flags.A: state = 'SYNACK'
        elif packet[TCP].flags.F or packet[TCP].flags.R: state = 'FIN'
        elif packet[TCP].flags.A: state = 'ACK'
    elif UDP in packet:
        state = 'INT'

    # Add connection event to LAST_N_CONNECTIONS
    LAST_N_CONNECTIONS.append({
        'timestamp': current_time,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'proto': proto,
        'service': service,
        'state': state,
        'src_port': src_port,
        'dst_port': dst_port
    })

    if flow_key not in FLOW_TABLE:
        FLOW_TABLE[flow_key] = {
            'start_time': current_time,
            'last_seen': current_time,
            'total_packets': 0,
            'total_bytes': 0,
            'src_packets': 0,
            'dst_packets': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'syn_flags': 0,
            'ack_flags': 0,
            'fin_flags': 0,
            'rst_flags': 0,
            'distinct_src_ports': {},
            'distinct_dst_ports': {},
            'protocol': proto,
            'service': service,
            'state': state,
            'min_ttl': 255,
            'max_ttl': 0,
            's_seq': 0,
            'd_seq': 0,
            's_win': 0,
            'd_win': 0,
            's_tcprtt': 0.0,
            'd_tcprtt': 0.0,
            's_smean': 0,
            'd_dmean': 0,
            'trans_depth': 0,
            'response_body_len': 0,
            'conn_count': 1
        }
    
    flow = FLOW_TABLE[flow_key]
    flow['last_seen'] = current_time
    flow['total_packets'] += 1
    flow['total_bytes'] += len(packet)

    if IP in packet:
        if packet[IP].src == flow_key.split('-')[0]:
            flow['src_packets'] += 1
            flow['src_bytes'] += len(packet)
        else:
            flow['dst_packets'] += 1
            flow['dst_bytes'] += len(packet)

        flow['min_ttl'] = min(flow['min_ttl'], packet[IP].ttl)
        flow['max_ttl'] = max(flow['max_ttl'], packet[IP].ttl)
    
    if TCP in packet:
        flow['distinct_src_ports'][packet[IP].src] = flow['distinct_src_ports'].get(packet[IP].src, set()).union({packet[TCP].sport})
        flow['distinct_dst_ports'][packet[IP].dst] = flow['distinct_dst_ports'].get(packet[IP].dst, set()).union({packet[TCP].dport})
        if packet[TCP].flags.S: flow['syn_flags'] += 1
        if packet[TCP].flags.A: flow['ack_flags'] += 1
        if packet[TCP].flags.F: flow['fin_flags'] += 1
        if packet[TCP].flags.R: flow['rst_flags'] += 1
        if packet[TCP].flags.F or packet[TCP].flags.R: flow['state'] = 'FIN'

        if packet[TCP].flags.S and packet[TCP].flags.A and not flow['synack']:
            flow['synack_time'] = current_time
        if packet[TCP].flags.A and flow.get('synack_time') and not flow['ackdat']:
            flow['ackdat_time'] = current_time
            flow['synack'] = flow['ackdat_time'] - flow['synack_time']
            flow['ackdat'] = current_time - flow['ackdat_time']

    elif UDP in packet:
        flow['distinct_src_ports'][packet[IP].src] = flow['distinct_src_ports'].get(packet[IP].src, set()).union({packet[UDP].sport})
        flow['distinct_dst_ports'][packet[IP].dst] = flow['distinct_dst_ports'].get(packet[IP].dst, set()).union({packet[UDP].dport})

def _clean_old_flows():
    """
    Removes old flows from the flow table based on FLOW_TIMEOUT and old connections from LAST_N_CONNECTIONS.
    """
    current_time = time.time()
    
    keys_to_delete_flow = [key for key, flow in FLOW_TABLE.items() if (current_time - flow['last_seen']) > FLOW_TIMEOUT]
    for key in keys_to_delete_flow:
        del FLOW_TABLE[key]

    while LAST_N_CONNECTIONS and (current_time - LAST_N_CONNECTIONS[0]['timestamp']) > FLOW_TIMEOUT:
        LAST_N_CONNECTIONS.popleft()

def extract_features(packet: Packet) -> dict:
    """
    Extracts features from a single packet and updates flow statistics.
    Returns a dictionary of features for the current flow.
    """
    _update_flow_table(packet)
    _clean_old_flows()

    features = {}
    flow_key = _get_flow_key(packet)

    if flow_key and flow_key in FLOW_TABLE:
        flow = FLOW_TABLE[flow_key]

        # Packet-level info
        features['timestamp'] = packet.time
        features['packet_size'] = len(packet)
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['proto'] = str(flow['protocol'])
        features['service'] = flow['service']
        features['state'] = flow['state']
        features['payload_len'] = len(packet[IP].payload) if packet[IP].payload else 0

        # Flow-based features (UNSW-NB15 inspired)
        duration = flow['last_seen'] - flow['start_time']
        features['dur'] = duration
        features['spkts'] = flow['src_packets']
        features['dpkts'] = flow['dst_packets']
        features['sbytes'] = flow['src_bytes']
        features['dbytes'] = flow['dst_bytes']
        features['rate'] = flow['total_packets'] / duration if duration > 0 else 0
        features['sload'] = (flow['src_bytes'] * 8) / duration if duration > 0 else 0
        features['dload'] = (flow['dst_bytes'] * 8) / duration if duration > 0 else 0

        features['synack'] = flow['synack']
        features['ackdat'] = flow['ackdat']
        
        # Simple packet inter-arrival times. More complex calculation needed for true sinpkt/dinpkt
        features['sinpkt'] = 0.0
        features['dinpkt'] = 0.0
        features['sjit'] = 0.0
        features['djit'] = 0.0
        features['swin'] = 0
        features['stcpb'] = 0
        features['dtcpb'] = 0
        features['dwin'] = 0
        features['tcprtt'] = features['synack'] + features['ackdat']

        features['smean'] = features['sbytes'] / features['spkts'] if features['spkts'] > 0 else 0
        features['dmean'] = features['dbytes'] / features['dpkts'] if features['dpkts'] > 0 else 0
        features['trans_depth'] = 0
        features['response_body_len'] = 0

        active_connections = [conn for conn in LAST_N_CONNECTIONS if (current_time - conn['timestamp']) <= FLOW_TIMEOUT]

        features['ct_srv_src'] = sum(1 for conn in active_connections if conn['service'] == features['service'] and conn['src_ip'] == features['src_ip'])
        features['ct_state_ttl'] = flow['min_ttl']
        features['ct_dst_ltm'] = sum(1 for conn in active_connections if conn['dst_ip'] == features['dst_ip'])
        features['ct_src_dport_ltm'] = len(flow['distinct_src_ports'].get(features['src_ip'], set()))
        features['ct_dst_sport_ltm'] = len(flow['distinct_dst_ports'].get(features['dst_ip'], set()))
        features['ct_dst_src_ltm'] = sum(1 for conn in active_connections if conn['dst_ip'] == features['dst_ip'] and conn['src_ip'] == features['src_ip'])
        features['ct_src_ltm'] = sum(1 for conn in active_connections if conn['src_ip'] == features['src_ip'])
        features['ct_srv_dst'] = sum(1 for conn in active_connections if conn['service'] == features['service'] and conn['dst_ip'] == features['dst_ip'])
        features['is_sm_ips_ports'] = 1 if features['src_ip'] == features['dst_ip'] and features.get('src_port') == features.get('dst_port') else 0

        features["pkt_ratio"] = features["spkts"] / (features["dpkts"] + 1) if features["dpkts"] >= 0 else 0
        features["byte_ratio"] = features["sbytes"] / (features["dbytes"] + 1) if features["dbytes"] >= 0 else 0
        features["syn_rate"] = flow['syn_flags'] / (features["spkts"] + 1) if features["spkts"] >= 0 else 0
        features["ack_rate"] = flow['ack_flags'] / (features["spkts"] + 1) if features["spkts"] >= 0 else 0
        features["avg_pkt_size"] = features["sbytes"] / (features["spkts"] + 1) if features["spkts"] >= 0 else 0

        features['bytes_per_pkt'] = (features['sbytes'] + features['dbytes']) / (features['spkts'] + features['dpkts'] + 1) if (features['spkts'] + features['dpkts'] + 1) > 0 else 0
        features['pkt_size_ratio'] = features['sbytes'] / (features['dbytes'] + 1) if features['dbytes'] >= 0 else 0
        features['port_diversity'] = (features['ct_src_dport_ltm'] + features['ct_dst_sport_ltm']) / (features['ct_srv_dst'] + 1) if (features['ct_srv_dst'] + 1) > 0 else 0


    return features