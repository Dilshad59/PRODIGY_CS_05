from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if TCP in packet or UDP in packet:
            if Raw in packet:
                payload = packet[Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"Payload: {decoded_payload}")
            else:
                print("No payload available.")
        else:
            print("Non-TCP/UDP packet.")
            
def start_sniffing():
    sniff(store=False, prn=packet_callback)

start_sniffing()
