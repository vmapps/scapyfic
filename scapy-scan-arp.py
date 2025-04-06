#!/usr/bin/env python3

import scapy.all as scapy
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def scan(target):

    packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')/scapy.ARP(pdst=target)
    answer, noanswer = scapy.srp(packet, timeout=1, verbose=False)
    
    for item in answer:
        # item = (sent packet, received packet)
        print( f'ARP reply from {item[1].psrc} ({item[1].hwsrc})' )

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        target = sys.argv[1]
        print(f'scan {target} with ARP')
        scan(target)
    else:
        print(f'Usage: {sys.argv[0]} <target|range>')
