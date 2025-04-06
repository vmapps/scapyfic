#!/usr/bin/env python3

import scapy.all as scapy
import sys

# --------------------------------------------------
# FUNCTIONS
# --------------------------------------------------
def ip2dns(host,resolver):

    arpa = host.split('.')[::-1]
    arpa = '.'.join(arpa)
    host = f'{arpa}.in-addr.arpa'

    layer_ip  = scapy.IP(dst=resolver)
    layer_udp = scapy.UDP(dport=53)
    layer_dns = scapy.DNS(
        rd=1,                                   # Recursive Desired
        qd=scapy.DNSQR(qname=host,qtype='PTR'), # Query Domain
    )

    try:
        answer = scapy.sr1(layer_ip/layer_udp/layer_dns, verbose=0)
        host = answer[scapy.DNS].an.rdata

        return str(host,'utf-8')[:-1]
    except:
        return  None
    
# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == '__main__':

    if len(sys.argv)==2:
        target = sys.argv[1]
        print( target,'name is',ip2dns(target,'8.8.8.8') )
    else:
        print(f'Usage: {sys.argv[0]} <ipaddr>')
