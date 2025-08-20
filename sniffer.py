from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        else:
            proto = "Other"

        payload = bytes(packet[IP].payload)[:50]  # show first 50 bytes only
        print(f"[{proto}] {src_ip} --> {dst_ip} | Payload: {payload}")

if __name__ == "__main__":
    print("Starting basic network sniffer... Press CTRL+C to stop.\n")
    sniff(prn=packet_callback, store=False)
