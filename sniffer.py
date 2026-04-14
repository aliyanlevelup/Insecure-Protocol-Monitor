#!/usr/bin/env python3

from scapy.all import sniff, TCP, Raw, IP
import os
import sys
import netifaces
import nmap


class Sniffer:

    def __init__(self, interface):
        self.interface = interface
        self.service_map = {}  # (ip, port) → service

    def check_root(self):
        if sys.platform.startswith('linux'):
            if os.geteuid() != 0:
                print('[+] Run as root user: sudo python3 sniffer.py <iface>')
                sys.exit(1)

    # 🔴 Nmap scan
    def run_nmap_scan(self, target):
        print(f"[+] Running nmap scan on {target}...")

        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sV -T4')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()

                for port in ports:
                    service = nm[host][proto][port]['name']
                    self.service_map[(host, port)] = service

        print("[+] Service Map Built:")
        for k, v in self.service_map.items():
            print(f"   {k} → {v}")

    # 🔵 DPI fallback detection
    def detect_protocol(self, payload):
        payload_lower = payload.lower()

        if payload.startswith(("GET", "POST", "HTTP/")):
            return "HTTP"

        elif payload.startswith("USER") or payload.startswith("PASS"):
            return "FTP"

        elif "login:" in payload_lower:
            return "TELNET"

        elif payload.startswith("SSH-"):
            return "SSH"

        return None

    def process_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):

            payload = packet[Raw].load.decode(errors="ignore")

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            protocol = None

            # 🔴 Check Nmap service map first
            if (dst_ip, dport) in self.service_map:
                protocol = self.service_map[(dst_ip, dport)]

            elif (src_ip, sport) in self.service_map:
                protocol = self.service_map[(src_ip, sport)]

            # 🔵 Fallback to DPI
            if not protocol:
                protocol = self.detect_protocol(payload)

            if protocol:
                print(f"[{protocol}] {src_ip}:{sport} → {dst_ip}:{dport}")
                print(f"   {payload[:100]}\n")

    def start(self):
        self.check_root()

        # 🔴 Ask for scan target
        target = input("[+] Enter target network (e.g. 192.168.1.0/24): ")
        self.run_nmap_scan(target)

        print(f"\n[+] Sniffing on {self.interface}...\n")

        sniff(
            iface=self.interface,
            prn=self.process_packet,
            store=False,
            filter="tcp"
        )


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: sudo python3 sniffer.py <interface>")
        print(f"Available interfaces: {netifaces.interfaces()}")
        sys.exit(1)

    iface = sys.argv[1]

    if iface not in netifaces.interfaces():
        print("[-] Invalid interface")
        sys.exit(1)

    sniffer = Sniffer(iface)
    sniffer.start()
