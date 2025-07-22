from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

#!! Function to process and print captured packets
def packet_callback(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")

        print(f"\n[{timestamp}] Protocol: {proto_name}")
        print(f"From: {ip_src} --> To: {ip_dst}")

        if TCP in packet:
            print(f"TCP Port: {packet[TCP].sport} --> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Port: {packet[UDP].sport} --> {packet[UDP].dport}")
        elif ICMP in packet:
            print("ICMP Packet")

        if Raw in packet:
            payload = packet[Raw].load
            try:
                print("Payload:")
                print(payload.decode(errors='ignore'))
            except:
                print("Payload (non-decodable)")


print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=False)
