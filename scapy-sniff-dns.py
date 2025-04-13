#!/usr/bin/env python3

import scapy.all as scapy
import socket
import sys

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------

dname = ''

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
    global dname

    req = p[scapy.DNS].qd.qname.decode('utf-8')[:-1]

    if( req != dname):
        dname = req
        print(f'[*] DNS request for {dname}')

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    filter = lambda p: p.haslayer(scapy.DNS) and p[scapy.UDP].dport==53 and p[scapy.DNS].opcode==0

    scapy.sniff(count=0,prn=display,lfilter=filter)
