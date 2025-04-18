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

    for ttl in range(1,maxttl+1):

        packet = scapy.IP(dst=dst,ttl=ttl)/scapy.ICMP(type='echo-request')
        answer = scapy.sr1(packet,timeout=2,verbose=False)

        # answer = (sent packet, received packet)
        if answer:
            # Destination reached
            answer.host = resolve(answer.src)
            rtt = (answer.time - packet.sent_time) * 1000
            print(f'[ttl={ttl:<2}] reply type {answer.type} from {answer.host} ({answer.src}) - {rtt:.2f} ms')
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

            print(f'traceroute to {target} ({sys.argv[1]})')
            trace(target)
        except:
            print(f'Unable to resolve {target}')
    else:
        print(f'Usage: {sys.argv[0]} <target>')
