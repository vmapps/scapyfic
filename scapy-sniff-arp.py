#!/usr/bin/env python3

import scapy.all as scapy

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def display(p):

    # ARP Request
    if p[scapy.ARP].op==1:
        print(f'[*] ARP request from {p.psrc} about {p.pdst}')

    # ARP Reply
    if p[scapy.ARP].op==2:
        print(f'[*] ARP reply from {p.psrc} ({p.hwsrc})')

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    # filter on packets with ARP layer 
    filter = lambda p: p.haslayer(scapy.ARP)

    scapy.sniff(count=0,prn=display,lfilter=filter)
