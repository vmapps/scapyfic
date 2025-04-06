#!/usr/bin/env python3

import scapy.all as scapy
import socket
import sys

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def resolve(addr):
    try:
        hst = socket.gethostbyaddr(addr)[0]
    except:
        hst = addr

    return hst

def trace(dst,maxttl=30):
    lay_ip = scapy.IP()
    lay_icmp = scapy.ICMP()

    for ttl in range(1,maxttl+1):

        packet = scapy.IP(dst=dst,ttl=ttl)/scapy.ICMP()
        answer = scapy.sr1(packet,timeout=2,verbose=False)

        if answer:
            # Destination reached
            answer.host = resolve(answer.src)
            print(f'[ttl={ttl:<2}] reply type {answer.type} from {answer.src} ({answer.host})')
            if answer.src == dst:
                break
        else:
            # Time out
            print(f'[ttl={ttl:<2}] timed out')

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        try:
            target = sys.argv[1]
            target = socket.gethostbyname(target)
            trace(target)
        except:
            print(f'Unable to resolve {target}')
    else:
        print(f'Usage: {sys.argv[0]} <target>')
