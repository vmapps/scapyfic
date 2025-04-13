#!/usr/bin/env python3

import scapy.all as scapy
import socket
import sys

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------

dhost =  ''

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def resolve(addr):
    try:
        hst = socket.gethostbyaddr(addr)[0]
    except:
        hst = addr

    return hst

def display(p):
    global dhost

    if( p[scapy.IP].dst != dhost):
        dhost = p[scapy.IP].dst
        dport = p[scapy.TCP].dport
        print(f'[*] HTTP/S request on tcp/{dport} to {resolve(dhost)} ({dhost})')

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    filter = lambda p: p.haslayer(scapy.TCP) and (p[scapy.TCP].dport==80 or p[scapy.TCP].dport==443)

    scapy.sniff(count=0,prn=display,lfilter=filter)
