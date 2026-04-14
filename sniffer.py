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


#  Nmap Scanner for service detect
class NmapScanner:
    def __init__(self):
        self.service_map = {}
        self.running = True

    def scan(self, target):
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sV -T4')

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]['name']
                    self.service_map[(host, port)] = service

    def start(self, target):
        while self.running:
            print(f"[+] Nmap scanning {target}...")
            self.scan(target)
            time.sleep(600)


# Packet Analyzer (DPI + Credentials)
class PacketAnalyzer:
    def __init__(self, service_map):
        self.service_map = service_map
        self.credentials = []
        self.packet_log = []
        self.packets = []

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

    def extract_credentials(self, payload):
        keywords = ["user", "pass", "login", "password", "authorization"]

        for k in keywords:
            if k in payload.lower():
                return payload.strip()
        return None

    def analyze(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):

            self.packets.append(packet)

            payload = packet[Raw].load.decode(errors="ignore")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            protocol = None

            if (dst_ip, dport) in self.service_map:
                protocol = self.service_map[(dst_ip, dport)]
            elif (src_ip, sport) in self.service_map:
                protocol = self.service_map[(src_ip, sport)]
            else:
                protocol = self.detect_protocol(payload)

            if protocol:
                log = f"{protocol} {src_ip}:{sport} → {dst_ip}:{dport}"
                self.packet_log.append(log)

                cred = self.extract_credentials(payload)
                if cred:
                    self.credentials.append(cred)


# Dashboard UI
class DashboardUI:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.running = True

    def build(self):
        table = Table(title="Live Sniffer Dashboard")
        table.add_column("Recent Traffic")
        table.add_column("Credentials")

        recent = "\n".join(self.analyzer.packet_log[-10:])
        creds = "\n".join(self.analyzer.credentials[-10:])

        table.add_row(recent, creds)
        return table

    def start(self):
        with Live(self.build(), refresh_per_second=2) as live:
            while self.running:
                live.update(self.build())
                time.sleep(1)


# Packet Sniffer
class PacketSniffer:
    def __init__(self, interface, analyzer):
        self.interface = interface
        self.analyzer = analyzer

    def start(self):
        sniff(
            iface=self.interface,
            prn=self.analyzer.analyze,
            store=False,
            filter="tcp"
        )


# Main App Controller
class SnifferApp:
    def __init__(self, interface):
        self.interface = interface
        self.scanner = NmapScanner()
        self.analyzer = PacketAnalyzer(self.scanner.service_map)
        self.ui = DashboardUI(self.analyzer)
        self.sniffer = PacketSniffer(interface, self.analyzer)

    def check_root(self):
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            print('[+] Run as root: sudo python3 sniffer.py <iface>')
            sys.exit(1)

    def run(self):
        self.check_root()

        target = input("[+] Enter target network (e.g. 192.168.1.0/24): ")

        # Threads
        threading.Thread(target=self.scanner.start, args=(target,), daemon=True).start()
        threading.Thread(target=self.ui.start, daemon=True).start()

        print(f"[+] Sniffing on {self.interface}...\n")

        try:
            self.sniffer.start()
        except KeyboardInterrupt:
            print("\n[+] Stopping... Saving PCAP")
            wrpcap("capture.pcap", self.analyzer.packets)


# Entry Point
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: sudo python3 sniffer.py <interface>")
        print(f"Available interfaces: {netifaces.interfaces()}")
        sys.exit(1)

    iface = sys.argv[1]

    if iface not in netifaces.interfaces():
        print("[-] Invalid interface")
        sys.exit(1)

    app = SnifferApp(iface)
    app.run()