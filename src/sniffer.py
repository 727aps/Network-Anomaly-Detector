import argparse
import asyncio
from scapy.all import sniff, wrpcap, IP, TCP
from rich.console import Console
from rich.table import Table
from src.utils import get_network_interfaces, setup_logging, log_alert

console = Console()

async def packet_sniffer(packet_queue: asyncio.Queue, interface: str = None, bpf_filter: str = None, save_file: str = None):
    """
    Sniffs live network packets from the specified interface and puts them into a queue.
    """
    captured_packets_for_save = []

    def process_packet(packet):
        if IP in packet:
            table = Table(title="Captured Packet")
            table.add_column("Field", justify="right", style="cyan", no_wrap=True)
            table.add_column("Value", style="magenta")
            table.add_row("Source", packet[IP].src)
            table.add_row("Destination", packet[IP].dst)
            table.add_row("Protocol", packet.summary())
            console.print(table)

            asyncio.create_task(packet_queue.put(packet))
            
            if save_file:
                captured_packets_for_save.append(packet)

    console.print(f"[bold green]Starting packet sniffing on interface: {interface}[/bold green]")
    try:
        sniff(prn=process_packet, iface=interface, filter=bpf_filter, store=False)
    except Exception as e:
        log_alert(f"Error during sniffing: {e}", level='ERROR')
    finally:
        if save_file and captured_packets_for_save:
            wrpcap(save_file, captured_packets_for_save)
            console.print(f"Packets saved to {save_file}")

