import json
import os
from datetime import datetime

class IPBlocker:
    def __init__(self, filename="blocked_ips.json"):
        self.filename = filename
        self.blocked_ips = self._load_blocked_ips()

    def _load_blocked_ips(self):
        if not os.path.exists(self.filename):
            return {}
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _save_blocked_ips(self):
        with open(self.filename, 'w') as f:
            json.dump(self.blocked_ips, f, indent=4)

    def block_ip(self, ip_address, reason="DDoS Attack Detected"):
        self.blocked_ips = self._load_blocked_ips() # Reload latest state
        if ip_address not in self.blocked_ips:
            self.blocked_ips[ip_address] = {
                "reason": reason,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "Blocked"
            }
            self._save_blocked_ips()
            print(f"🚫 [SIMULATION] IP {ip_address} has been blocked. Reason: {reason}")
            return True
        return False

    def unblock_ip(self, ip_address):
        self.blocked_ips = self._load_blocked_ips() # Reload latest state
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            self._save_blocked_ips()
            print(f"✅ [SIMULATION] IP {ip_address} has been unblocked.")
            return True
        return False

    def clear_all(self):
        self.blocked_ips = {}
        self._save_blocked_ips()
        print("✅ [SIMULATION] All IPs have been unblocked/reset.")
        return True

    def get_blocked_ips(self):
        self.blocked_ips = self._load_blocked_ips() # Reload latest state
        return self.blocked_ips

if __name__ == "__main__":
    # Test the blocker
    blocker = IPBlocker()
    blocker.block_ip("192.168.1.100", "High packet rate")
    print("Blocked IPs:", blocker.get_blocked_ips())
    # blocker.unblock_ip("192.168.1.100")
