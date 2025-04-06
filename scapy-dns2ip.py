#!/usr/bin/env python3

import scapy.all as scapy
import sys

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def dns2ip(host,resolver):

    layer_ip  = scapy.IP(dst=resolver)
    layer_udp = scapy.UDP(dport=53)
    layer_dns = scapy.DNS(
        rd=1,                                   # Recursive Desired
        qd=scapy.DNSQR(qname=host,qtype='A'),   # Query Domain
    )

    try:
        answer = scapy.sr1(layer_ip/layer_udp/layer_dns, verbose=0)
        ips=[]
        for item in answer[scapy.DNS].an:
            if not isinstance(item.rdata,bytes):
                ips.append(item.rdata)
        return ips
    except:
        return None

# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        target = sys.argv[1]
        print( target,'address is',dns2ip(target,'8.8.8.8') )
    else:
        print(f'Usage: {sys.argv[0]} <host>')
