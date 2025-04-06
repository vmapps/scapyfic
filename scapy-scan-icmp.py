#!/usr/bin/env python3

import scapy.all as scapy
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def scan(target):

    packet = scapy.IP(dst=target)/scapy.ICMP()
    answer, noanswer = scapy.sr(packet, timeout=1, verbose=False)
    
    for item in answer:
        # item = (sent packet, received packet)
        if item[1].type == 0:
            print( f'ICMP echo-reply from {item[1].src}' )

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        target = sys.argv[1]
        print(f'scan {target} with ICMP')
        scan(target)
    else:
        print(f'Usage: {sys.argv[0]} <target|range>')
