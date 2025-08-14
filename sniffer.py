
import argparse
import csv
import os
from datetime import datetime
from scapy.all import sniff, IP
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.utils import wrpcap

captured_packets = []
parsed_results = []

def ensure_dir_for_file(filepath):
    """Create directory for a given file path if needed."""
    dir_path = os.path.dirname(os.path.abspath(filepath))
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path)

def process_packet(packet):
    """Extract and display key packet information."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload_len = len(packet[IP].payload)
        time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        elif proto == 1:
            proto_name = "ICMP"
        else:
            proto_name = str(proto)

        parsed_results.append([time_str, src_ip, dst_ip, proto_name, payload_len])
        captured_packets.append(packet)

        print(f"[{time_str}] [{proto_name}] {src_ip} → {dst_ip} | Payload: {payload_len} bytes")

def save_pcap(filename):
    """Save captured packets to PCAP."""
    if captured_packets:
        ensure_dir_for_file(filename)
        wrpcap(filename, captured_packets)
        print(f"[+] Saved PCAP file: {filename}")
    else:
        print("[-] No packets to save to PCAP.")

def save_csv(filename):
    """Save parsed results to CSV."""
    if parsed_results:
        ensure_dir_for_file(filename)
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Payload Length"])
            writer.writerows(parsed_results)
        print(f"[+] Saved CSV file: {filename}")
    else:
        print("[-] No parsed data to save to CSV.")

def main():
    parser = argparse.ArgumentParser(description="Python Network Packet Sniffer")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--filter", type=str, default="", help="BPF filter (e.g., 'tcp', 'udp', 'icmp')")
    parser.add_argument("--pcap", type=str, help="Path to save PCAP file")
    parser.add_argument("--csv", type=str, help="Path to save CSV file")
    args = parser.parse_args()

    print("[*] Starting packet capture... Press Ctrl+C to stop.")

    try:
        sniff(prn=process_packet, filter=args.filter, store=False, count=args.count)
    except PermissionError:
        print("[-] Permission denied. Run as Administrator (Windows) or with sudo (Linux/Mac).")
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")

    if args.pcap:
        save_pcap(args.pcap)
    if args.csv:
        save_csv(args.csv)

if __name__ == "__main__":
    main()
