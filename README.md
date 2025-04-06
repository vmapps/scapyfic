# scapyfic

Various tools based on Scapy

## Scapy Traceroute

Sample script to trace IP route to a target.

```
python3  scapy-traceroute.py
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
