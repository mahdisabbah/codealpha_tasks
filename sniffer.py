from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"IP: {ip_src} -> {ip_dst} | Protocol: {proto}")
        if TCP in packet:
            print(f"TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}")
        print(f"Payload: {bytes(packet.payload)[:50]}...\n")

print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=20)  # captures 20 packets