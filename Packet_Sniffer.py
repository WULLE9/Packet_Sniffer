from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

from scapy.packet import Raw


def packet_sniffer(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        if packet.haslayer(TCP):
            protocol_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
        else:
            protocol_name = "Other"
            src_port = "N/A"
            dst_port = "N/A"

        print(f"[{timestamp}] Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}:{src_port}")
        print(f"Destination IP: {dst_ip}:{dst_port}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")
        else:
            print("Payload: None")
        print("-" * 50)


def start_sniffing(interface):
    print(f"Starting packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=packet_sniffer, store=False)


if __name__ == "__main__":
    start_sniffing(interface="your_interface")
