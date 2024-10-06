from scapy.all import *

# Target IP address and port
target_ip = "192.168.1.100"
target_port = 80

# Honeypot IP address and port
honeypot_ip = "192.168.1.101"
honeypot_port = 80

# Function to handle incoming packets
def handle_packet(packet):
    # Check if the packet is a TCP SYN packet
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # Create a TCP packet with a SYN/ACK flag
        ack_packet = IP(src=honeypot_ip, dst=packet[IP].src) / TCP(sport=honeypot_port, dport=packet[TCP].sport, flags='SA', seq=packet[TCP].seq, ack=packet[TCP].seq+1)
        send(ack_packet)
        # Log the attacker's IP, port, and time
        print(f"Attacker IP: {packet[IP].src}, Port: {packet[TCP].sport}, Time: {packet.time}")

# Sniff packets on the target port
sniff(filter=f"tcp and dst port {target_port}", prn=handle_packet)