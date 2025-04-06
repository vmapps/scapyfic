# scapyfic

Various tools based on Scapy

## Scapy Awesome

Some helpful scapy commands.

```
import scapy.all as scapy

# Scapy documentation
print( scapy.sniff.__doc__ )

# Sniff traffic
packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p.summary()
    )

# Sniff traffic filtering on IP layer
packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p.summary(),
    lfilter=lambda p:p.haslayer(scapy.IP)
    )

# Sniff traffic filtering on UDP layer
packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p.summary(),
    lfilter=lambda p:p.haslayer(scapy.UDP)
    )

# Sniff traffic filtering on DNS layer
packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p.summary(),
    lfilter=lambda p:p.haslayer(scapy.DNS)
    )

# Sniff traffic filtering on DNS Queries
packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p.summary(),
    lfilter=lambda p:p.haslayer(scapy.DNS) and p.getlayer(scapy.DNS).qr==0
    )

packets = scapy.sniff(
    count=0,
    iface='en0',
    prn=lambda p:p[scapy.DNS].qd.qname.decode('utf-8'),
    lfilter=lambda p:p.haslayer(scapy.DNS) and p.getlayer(scapy.DNS).qr==0
    )
```

## Scapy DNS2IP

Sample script to resolve DNS name into IP addresses.

```
$ python3 scapy-dns2ip.py
Usage: scapy-dns2ip.py <host>

$ python3 scapy-dns2ip.py www.fmac.com
www.fmac.com address is ['3.33.251.168', '15.197.225.128']
```

## Scapy IP2DNS

Sample script to resolve IP address into DNS name.

```
$ python3 scapy-ip2dns.py
Usage: scapy-ip2dns.py <ipaddr>

$ python3 scapy-ip2dns.py 2.20.10.35
2.20.10.35 name is a2-20-10-35.deploy.static.akamaitechnologies.com
```

## Scapy Traceroute

Sample script to trace IP route to a target.

```
$ python3 scapy-traceroute.py
Usage: scapy-traceroute.py <target>
```

What is script doing :

- get `target` from command line with `sys.argv`
- resolve name to IP address with `socket.gethostbyname()`
- enter loop to send packets with `ttl=1`until `target` reached or `ttl=maxttl`
  - create packet with layer `scapy.ICMP()` under `scapy.IP()`
  - set `dst`and `ttl`values for `scapy.IP()`
  - set `type` value for `scapy.ICMP()`
  - send one `IP()/ICMP()` packet with `scapy.sr1()`
  - if no packet returned, display timeout message
  - else print source of `ICMP`packet received
  - if packet received from `target`, then break the loop
