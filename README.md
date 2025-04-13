# scapyfic

Collection of various Python scripts using Scapy library to scan networks, sniff traffic or traceroute packets :

- [Scapy Awesome](#scapy-awesome)
- [Scapy DNS2IP](#scapy-dns2ip)
- [Scapy IP2DNS](#scapy-ip2dns)
- [Scapy Scan ARP](#scapy-scan-arp)
- [Scapy Scan ICMP](#scapy-scan-icmp)
- [Scapy Scan TCP SYN](#scapy-scan-tcp-syn)
- [Scapy Sniff ARP](#scapy-sniff-arp)
- [Scapy Sniff DNS](#scapy-sniff-dns)
- [Scapy Sniff WEB](#scapy-sniff-web)
- [Scapy Sniff WIFI](#scapy-sniff-wifi)
- [Scapy Traceroute](#scapy-traceroute)

## Scapy Awesome

Some helpful scapy commands.

```
$ scapy

>>> # List layers
>>> ls()

>>> # List IP layer default values
>>> ls(IP)

>>> # List commands
>>> lsc()

>>> # Help with sr1 function
>>> help(sr1)

>>> # Quit
>>> quit()
```

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

Note: more tips and tricks in document "[Network packet manipulation with Scapy](http://scapy.net/talks/scapy_hack.lu.pdf)" (Philippe BIONDI, 2015)

## Scapy DNS2IP

Sample script to resolve DNS name into IP addresses.

```
$ python3 scapy-dns2ip.py
Usage: scapy-dns2ip.py <host>

$ python3 scapy-dns2ip.py www.fmac.com
www.fmac.com address is ['3.33.251.168', '15.197.225.128']
```

What is script doing :

- get `target` from command line with `sys.argv`
- create layer from `scapy.IP()` and set resolver address using `dst`
- create layer from `scapy.UDP()` and set destination port using `dport`
- create layer from `scapy.DNS()` and `scapy.DNQR()` to set query using `qname` and `qtype`
- forge packet from layers previously created with `scapy.sr1()`
- return `an.rdata` array of results from `scapy.DNS()` entries

## Scapy IP2DNS

Sample script to resolve IP address into DNS name.

```
$ python3 scapy-ip2dns.py
Usage: scapy-ip2dns.py <ipaddr>

$ python3 scapy-ip2dns.py 2.20.10.35
2.20.10.35 name is a2-20-10-35.deploy.static.akamaitechnologies.com
```

What is script doing :

- get `target` from command line with `sys.argv`
- convert IP address to `in-addr.arpa` format
- create layer from `scapy.IP()` and set resolver address using `dst`
- create layer from `scapy.UDP()` and set destination port using `dport`
- create layer from `scapy.DNS()` and `scapy.DNQR()` to set query using `qname` and `qtype`
- forge packet from layers previously created with `scapy.sr1()`
- return `an.rdata` result from `scapy.DNS()` entry

## Scapy Scan ARP

Sample script to scan IP target (or range) with ARP.

```
$ python3 scapy-scan-arp.py
Usage: scapy-scan-arp.py <target|range>

$ python3 scapy-scan-arp.py 192.168.0.119
scan 192.168.0.119 with ARP
ARP reply from 192.168.0.119 (80:16:12:c5:b2:2c)
```

What is script doing :

- get `target` from command line with `sys.argv`
- create packet with layer `scapy.Ether()` under `scapy.ARP()`
- set `dst` for `scapy.Ether()` to use broadcast address
- set `pdst` for `scapy.ARP()`
- send one `Ether()/ARP()` packet with `scapy.srp()`
- display packets `src` and `hwsrc` from answers received

## Scapy Scan ICMP

Sample script to scan IP target (or range) with ICMP.

```
$ python3 scapy-scan-icmp.py
Usage: scapy-scan-icmp.py <target|range>

$ python3 scapy-scan-icmp.py 192.168.1.0/24
scan 192.168.1.0/24 with ICMP
ICMP echo-reply from 192.168.1.1
ICMP echo-reply from 192.168.1.51
ICMP echo-reply from 192.168.1.52
```

What is script doing :

- get `target` from command line with `sys.argv`
- create packet with layer `scapy.ICMP()` under `scapy.IP()`
- set `dst` for `scapy.IP()`
- send one `IP()/ICMP()` packet with `scapy.sr()`
- display packets being type of `echo-reply` from answers received

## Scapy Scan TCP SYN

Sample script to scan IP target (or range) with TCP SYN flag.

```
$ python3 scapy-scan-tcpsyn.py
Usage: scapy-scan-tcpsyn.py <target|range>

$ python3 scapy-scan-tcpsyn.py 192.168.0.0/24
scan 192.168.0.0/24 with TCP SYN
TCP SYN reply from 192.168.0.1
TCP SYN reply from 192.168.0.92
TCP SYN reply from 192.168.0.118
TCP SYN reply from 192.168.0.161
TCP SYN reply from 192.168.0.203
```

What is script doing :

- get `target` from command line with `sys.argv`
- create packet with layer `scapy.ICMP()` under `scapy.TCP()`
- set `dst` for `scapy.IP()`
- set `dport` and `flags` for `scapy.TCP()`
- send one `IP()/TCP()` packet with `scapy.sr()`
- display packets having proto set to `tcp` from answers received

## Scapy Sniff ARP

Sample script to sniff ARP requests and replies.

```
$ python3 scapy-sniff-arp.py
[*] ARP request from 192.168.0.1 about 192.168.0.12
[*] ARP reply from 192.168.0.12 (46:c8:54:4e:6c:14)
[*] ARP request from 192.168.0.1 about 192.168.0.19
[*] ARP reply from 192.168.0.19 (85:85:80:22:1f:20)
```

## Scapy Sniff DNS

Sample script to sniff DNS requests.

```
$ python3 scapy-sniff-dns.py
[*] DNS request to 1.1.1.1 for ogads-pa.clients6.google.com
[*] DNS request to 1.1.1.1 for www.youtube.com
[*] DNS request to 1.1.1.1 for fonts.googleapis.com
[*] DNS request to 1.0.0.1 for news.google.com
[*] DNS request to 1.0.0.1 for accounts.google.com
[*] DNS request to 1.0.0.1 for www.gstatic.com
```

## Scapy Sniff WEB

Sample script to sniff request to HTTP and HTTPS hosts.

```
$ python3 scapy-sniff-web.py
[*] HTTP/S request on tcp/443 to 172.64.155.119 (172.64.155.119)
[*] HTTP/S request on tcp/443 to 104.18.87.42 (104.18.87.42)
[*] HTTP/S request on tcp/443 to server-52-84-90-49.lhr62.r.cloudfront.net (52.84.90.49)
[*] HTTP/S request on tcp/443 to a2-20-10-35.deploy.static.akamaitechnologies.com (2.20.10.35)
[*] HTTP/S request on tcp/443 to server-52-84-90-49.lhr62.r.cloudfront.net (52.84.90.49)
[*] HTTP/S request on tcp/443 to ip-72-163-15-141.cisco.com (72.163.15.141)
```

## Scapy Sniff WIFI

Sample script to sniff WIFI broadcasts.

```
$ python3 scapy-sniff-wifi.py
[*] WIFI broadcast from Gateway (a0:ae:77:05:c6:42)
[*] WIFI broadcast from AccessP_5G (13:fa:45:f1:80:66)
[*] WIFI broadcast from Gateway (a0:ae:77:05:c6:42)
[*] WIFI broadcast from AccessP_5G (13:fa:45:f1:80:66)
```

## Scapy Traceroute

Sample script to trace IP route to a target.

```
$ python3 scapy-traceroute.py
Usage: scapy-traceroute.py <target>

$ python3 scapy-traceroute.py www.cisco.com
traceroute to 2.20.10.35 (www.cisco.com)
[ttl=1 ] reply type 11 from 192.168.0.1 (192.168.0.1) - 5.00 ms
[ttl=2 ] reply type 11 from 192.168.1.1 (192.168.1.1) - 1.92 ms
[ttl=3 ] timed out
[ttl=4 ] timed out
[ttl=5 ] timed out
[ttl=6 ] timed out
[ttl=7 ] reply type 11 from 193.251.131.8 (193.251.131.8) - 158.98 ms
[ttl=8 ] reply type 11 from 81.52.187.80 (81.52.187.80) - 13.46 ms
[ttl=9 ] reply type 0 from a2-20-10-35.deploy.static.akamaitechnologies.com (2.20.10.35) - 15.20 ms
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
