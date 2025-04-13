#!/usr/bin/env python3

import scapy.all as scapy
import socket
import sys

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------

dinfo = ''

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def display(p):
    global dinfo

    try:
        req = p.info.decode('utf-8') or '???'
    except:
        return

    if( req != dinfo):
        dinfo = req
        daddr = p.addr2
        print(f'[*] WIFI broadcast from {dinfo} ({daddr})')

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    scapy.conf.use_pcap=True

    # filter on packets with DOT11 layer with Beacons (type=0 and subtype=8) 
    # filter = lambda p: p.haslayer(scapy.Dot11)
    filter = lambda p: p.haslayer(scapy.Dot11) and p[scapy.Dot11].type==0 and p[scapy.Dot11].subtype==8

    scapy.sniff(count=0,prn=display,lfilter=filter,monitor=True)
