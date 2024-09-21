Key Components of the Program:
packet_sniffer Function: This function is called every time a packet is captured. It analyzes the packet for IP, TCP, UDP, and ICMP layers, displaying relevant information such as:

Source and Destination IP addresses
Ports (for TCP/UDP protocols)
Protocol type (TCP, UDP, ICMP, or Other)
Payload data if present (e.g., raw data transmitted in the packet)
Interface Selection: The program captures packets from a specified network interface. You will need to replace 'your_interface' in the code with your actual network interface (e.g., 'eth0' for wired or 'wlan0' for wireless).

Protocols: The tool handles common protocols such as:
TCP: Transmission Control Protocol
UDP: User Datagram Protocol
ICMP: Internet Control Message Protocol
Packet Sniffing: The sniff function captures packets on the specified network interface. The prn parameter is set to the packet_sniffer function to process each packet as it arrives.
