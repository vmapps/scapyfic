#!/usr/bin/env python3

import scapy.all as scapy
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def scan(target):

    packet = scapy.IP(dst=target)/scapy.TCP(dport=1,flags='S')
    answer, noanswer = scapy.sr(packet, timeout=0.50, verbose=False)
    
    for item in answer:
        # item = (sent packet, received packet)
        if item[1].proto == 6:
            print( f'TCP SYN reply from {item[1].src}' )

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        target = sys.argv[1]
        print(f'scan {target} with TCP SYN')
        scan(target)
    else:
        print(f'Usage: {sys.argv[0]} <target|range>')
