import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw
import time
from src.features import extract_features, FLOW_TABLE, LAST_N_CONNECTIONS, FLOW_TIMEOUT

@pytest.fixture(autouse=True)
def clear_flow_table():
    FLOW_TABLE.clear()
    LAST_N_CONNECTIONS.clear()
    yield

def test_extract_features_tcp_syn():
    packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.10", proto=6, ttl=64)/TCP(sport=10000, dport=80, flags="S")
    features = extract_features(packet)

    assert features is not None
    assert features['src_ip'] == "192.168.1.1"
    assert features['dst_ip'] == "192.168.1.10"
    assert features['proto'] == "6"
    assert features['service'] == "http"
    assert features['state'] == "SYN"
    assert features['spkts'] == 1
    assert features['dpkts'] == 0
    assert features['synack'] == 0.0

def test_extract_features_tcp_synack_fin():
    # Simulate SYN
    packet1 = Ether()/IP(src="192.168.1.1", dst="192.168.1.10", proto=6, ttl=64)/TCP(sport=10000, dport=80, flags="S")
    extract_features(packet1)
    time.sleep(0.01)

    # Simulate SYN-ACK
    packet2 = Ether()/IP(src="192.168.1.10", dst="192.168.1.1", proto=6, ttl=128)/TCP(sport=80, dport=10000, flags="SA")
    features_synack = extract_features(packet2)
    time.sleep(0.01)

    # Simulate FIN
    packet3 = Ether()/IP(src="192.168.1.1", dst="192.168.1.10", proto=6, ttl=64)/TCP(sport=10000, dport=80, flags="FA")
    features_fin = extract_features(packet3)

    assert features_synack['state'] == "SYNACK"
    assert features_fin['state'] == "FIN"
    assert features_fin['synack'] > 0
    assert features_fin['ackdat'] > 0

def test_extract_features_udp():
    packet = Ether()/IP(src="1.1.1.1", dst="8.8.8.8", proto=17, ttl=64)/UDP(sport=50000, dport=53)/Raw(load="dns query")
    features = extract_features(packet)

    assert features is not None
    assert features['proto'] == "17"
    assert features['service'] == "dns"
    assert features['state'] == "INT"
    assert features['payload_len'] > 0

def test_flow_timeout():
    packet1 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2", proto=6, ttl=64)/TCP(sport=1000, dport=2000, flags="S")
    extract_features(packet1)

    assert len(FLOW_TABLE) == 1
    flow_key = list(FLOW_TABLE.keys())[0]

    time.sleep(FLOW_TIMEOUT + 1) # Wait for flow to timeout

    packet2 = Ether()/IP(src="10.0.0.1", dst="10.0.0.2", proto=6, ttl=64)/TCP(sport=1000, dport=2000, flags="A")
    extract_features(packet2) # This packet should create a new flow as the old one timed out

    assert len(FLOW_TABLE) == 1
    new_flow_key = list(FLOW_TABLE.keys())[0]
    assert flow_key == new_flow_key
    assert FLOW_TABLE[new_flow_key]['total_packets'] == 1

def test_derived_features():
    packet = Ether()/IP(src="192.168.0.1", dst="192.168.0.2", proto=6, ttl=64)/TCP(sport=1000, dport=80, flags="S")
    features = extract_features(packet)

    assert "pkt_ratio" in features
    assert "byte_ratio" in features
    assert "syn_rate" in features
    assert "ack_rate" in features
    assert "avg_pkt_size" in features
    assert "bytes_per_pkt" in features
    assert "pkt_size_ratio" in features
    assert "port_diversity" in features

def test_ct_features():
    # Simulate multiple connections to test ct_ features
    p1 = Ether()/IP(src="1.1.1.1", dst="1.1.1.10", proto=6, ttl=64)/TCP(sport=1000, dport=80, flags="S")
    p2 = Ether()/IP(src="1.1.1.1", dst="1.1.1.11", proto=6, ttl=64)/TCP(sport=1001, dport=80, flags="S")
    p3 = Ether()/IP(src="1.1.1.2", dst="1.1.1.10", proto=6, ttl=64)/TCP(sport=1002, dport=80, flags="S")
    p4 = Ether()/IP(src="1.1.1.1", dst="1.1.1.10", proto=17, ttl=64)/UDP(sport=1003, dport=53)

    f1 = extract_features(p1)
    time.sleep(0.1)
    f2 = extract_features(p2)
    time.sleep(0.1)
    f3 = extract_features(p3)
    time.sleep(0.1)
    f4 = extract_features(p4)

    # Test ct_dst_ltm (count of connections to same destination IP)
    # p1, p3, p4 all have dst_ip 1.1.1.10 or 1.1.1.11. Need to be careful with definition.
    # Based on our simple implementation using LAST_N_CONNECTIONS, it counts active connections.
    # For f1 (dst 1.1.1.10):
    assert f1['ct_dst_ltm'] == 1 # Only one connection to 1.1.1.10 so far
    # For f2 (dst 1.1.1.11):
    assert f2['ct_dst_ltm'] == 1 # Only one connection to 1.1.1.11 so far
    # For f3 (dst 1.1.1.10):
    assert f3['ct_dst_ltm'] == 2 # Two connections to 1.1.1.10 (p1 and p3)
    # For f4 (dst 1.1.1.10):
    assert f4['ct_dst_ltm'] == 3 # Three connections to 1.1.1.10 (p1, p3, p4)

    # Test ct_src_ltm (count of connections from same source IP)
    assert f1['ct_src_ltm'] == 1
    assert f2['ct_src_ltm'] == 2 # p1, p2 from 1.1.1.1
    assert f3['ct_src_ltm'] == 1 # p3 from 1.1.1.2
    assert f4['ct_src_ltm'] == 3 # p1, p2, p4 from 1.1.1.1

    # Test ct_srv_dst (count of connections to same service and destination IP)
    # For f1 (service http, dst 1.1.1.10):
    assert f1['ct_srv_dst'] == 1
    # For f2 (service http, dst 1.1.1.11):
    assert f2['ct_srv_dst'] == 1
    # For f3 (service http, dst 1.1.1.10):
    assert f3['ct_srv_dst'] == 2 # p1 and p3
    # For f4 (service dns, dst 1.1.1.10):
    assert f4['ct_srv_dst'] == 1 # p4 is the only dns to 1.1.1.10

def test_is_sm_ips_ports():
    # Same IP, same port (example of internal communication or loopback)
    p1 = Ether()/IP(src="127.0.0.1", dst="127.0.0.1", proto=6, ttl=64)/TCP(sport=1000, dport=1000, flags="S")
    f1 = extract_features(p1)
    assert f1['is_sm_ips_ports'] == 1

    # Same IP, different port
    p2 = Ether()/IP(src="127.0.0.1", dst="127.0.0.1", proto=6, ttl=64)/TCP(sport=1000, dport=1001, flags="S")
    f2 = extract_features(p2)
    assert f2['is_sm_ips_ports'] == 0

    # Different IP, same port
    p3 = Ether()/IP(src="192.168.1.1", dst="192.168.1.2", proto=6, ttl=64)/TCP(sport=1000, dport=1000, flags="S")
    f3 = extract_features(p3)
    assert f3['is_sm_ips_ports'] == 0

