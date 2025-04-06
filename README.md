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

# DNS Queries
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

## Scapy Traceroute

Sample script to trace IP route to a target.

```

python3 scapy-traceroute.py
Usage: scapy-traceroute.py <target>

```

How script is running :

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

```

```
