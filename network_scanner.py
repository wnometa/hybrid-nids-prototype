#!/usr/bin/env python3
from scapy.all import Ether, ARP, srp

def scan_local_wifi(ip_range):
    print(f"[*] Scanning local network range: {ip_range}...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    answered_list = srp(packet, timeout=2, verbose=False)[0]
    #!/usr/bin/env python3
from scapy.all import Ether, ARP, srp

def scan_local_wifi(ip_range):
    print(f"[*] Scanning local network range: {ip_range}...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    answered_list = srp(packet, timeout=2, verbose=False)[0]
    
    print("\n--- Discovered Devices on Your Wi-Fi ---")
    print(f"{'IP Address':<18} | {'MAC Address':<18}")
    print("-" * 40)
    
    for element in answered_list:
        print(f"{element[1].psrc:<18} | {element[1].hwsrc:<18}")

if __name__ == "__main__":
    target_subnet = "192.168.0.0/24" 
    scan_local_wifi(target_subnet)
