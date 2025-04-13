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

    # filter on packets with DNS layer and DNS query (opcode=0) on destination port 43 
    filter = lambda p: p.haslayer(scapy.DNS) and p[scapy.UDP].dport==53 and p[scapy.DNS].opcode==0

    scapy.sniff(count=0,prn=display,lfilter=filter)
