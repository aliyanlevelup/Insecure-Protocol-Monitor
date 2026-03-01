#!/usr/bin/env python3

from scapy.all import sniff
import signal
import os
import sys
import netifaces
import threading



class Sniffer:

    def __init__(self, interface: list = sniff_iface):
        self.interface = interface
    
    def start_sniff(self):
        if sys.platform.startswith('linux'):
            if os.geteuid() != 0:
            print('[+] run as root user. sudo ./sniffer.py iface')
            sys.exit(1)

    sniff_iface = sys.argv[1] if sys.argv[1] in netifaces.interfaces
    
    sniff(iface=[sniff_iface], store=False)




