import argparse
from scapy.all import sniff, wrpcap, IP, TCP
from rich.console import Console
from rich.table import Table
from anomaly_detection import classify_anomaly  # Import anomaly detection

def get_args():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("--protocol", type=str, help="Filter packets by protocol (e.g., tcp, udp, icmp)")
    parser.add_argument("--port", type=int, help="Filter packets by port (e.g., 80, 443)")
    parser.add_argument("--ip", type=str, help="Filter packets by source/destination IP")
    parser.add_argument("--save", type=str, help="Save captured packets to a file (e.g., packets.pcap)")
    return parser.parse_args()

console = Console()

def packet_sniffer(protocol=None, port=None, ip=None, save_file=None):
    """
    Sniffs network packets and optionally filters them by protocol, port, or IP.
    Also saves captured packets to a file if specified.
    """
    captured_packets = []

    def process_packet(packet):
        if protocol and protocol.lower() not in packet.summary().lower():
            return
        if port and packet.haslayer(TCP) and packet[TCP].dport != port:
            return
        if ip and ip not in packet.summary():
            return
        
        if packet.haslayer(IP):
            table = Table(title="Captured Packet")
            table.add_column("Field", justify="right", style="cyan", no_wrap=True)
            table.add_column("Value", style="magenta")
            table.add_row("Source", packet[IP].src)
            table.add_row("Destination", packet[IP].dst)
            table.add_row("Protocol", packet.summary())
            console.print(table)

            packet_features = {
                'packet_size': len(packet),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'payload': str(packet.payload)
            }

            anomaly_label = classify_anomaly(packet_features)
            console.print(f"[bold red]Anomaly Detected: {anomaly_label}[/bold red]" if anomaly_label != 'Normal' else "[bold green]Safe Packet[/bold green]")
        
        captured_packets.append(packet)

    sniff(prn=process_packet, store=False)

    if save_file:
        wrpcap(save_file, captured_packets)
        print(f"Packets saved to {save_file}")

if __name__ == "__main__":
    args = get_args()
    packet_sniffer(protocol=args.protocol, port=args.port, ip=args.ip, save_file=args.save)
