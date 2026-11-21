#!/usr/bin/env python3
"""Create samples/sample_traffic.pcap from FICTIONAL packets (never sent on a
network). Lets you demo and test the sniffer without root or live traffic.
Addresses use the reserved documentation ranges (RFC 5737)."""
import os
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

CLIENT, SERVER, DNS_SRV = "192.0.2.10", "198.51.100.20", "192.0.2.53"
GATEWAY, SCANNER = "192.0.2.1", "203.0.113.99"
MAC_C, MAC_G, MAC_X = "aa:aa:aa:aa:aa:10", "aa:aa:aa:aa:aa:01", "de:ad:be:ef:00:99"
eth = lambda s, d: Ether(src=s, dst=d)
pkts = []

pkts.append(eth(MAC_C, MAC_G) / ARP(op=1, psrc=CLIENT, pdst=GATEWAY, hwsrc=MAC_C))
pkts.append(eth(MAC_G, MAC_C) / ARP(op=2, psrc=GATEWAY, pdst=CLIENT, hwsrc=MAC_G, hwdst=MAC_C))
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=40001, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
pkts.append(eth(MAC_G, MAC_C) / IP(src=DNS_SRV, dst=CLIENT) / UDP(sport=53, dport=40001) / DNS(qr=1, qd=DNSQR(qname="example.com")))
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / ICMP(type=8) / Raw(b"ping"))
pkts.append(eth(MAC_G, MAC_C) / IP(src=SERVER, dst=CLIENT) / ICMP(type=0) / Raw(b"ping"))

# TCP handshake + cleartext HTTP
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / TCP(sport=51000, dport=80, flags="S", seq=100))
pkts.append(eth(MAC_G, MAC_C) / IP(src=SERVER, dst=CLIENT) / TCP(sport=80, dport=51000, flags="SA", seq=500, ack=101))
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / TCP(sport=51000, dport=80, flags="A", seq=101, ack=501))
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / TCP(sport=51000, dport=80, flags="PA", seq=101, ack=501)
            / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: demo\r\n\r\n"))
pkts.append(eth(MAC_G, MAC_C) / IP(src=SERVER, dst=CLIENT) / TCP(sport=80, dport=51000, flags="PA", seq=501, ack=180)
            / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>"))
# Fictional login form posted over HTTP (shows credential redaction)
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / TCP(sport=51001, dport=80, flags="PA")
            / Raw(b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=demo&password=not-a-real-password"))
# HTTPS: handshake and encrypted data are unreadable
pkts.append(eth(MAC_C, MAC_G) / IP(src=CLIENT, dst=SERVER) / TCP(sport=51002, dport=443, flags="PA") / Raw(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"))
pkts.append(eth(MAC_G, MAC_C) / IP(src=SERVER, dst=CLIENT) / TCP(sport=443, dport=51002, flags="PA") / Raw(b"\x17\x03\x03\x00\x20" + bytes(range(32))))

# Simulated SYN scan (20 ports) - written to a file only
for port in range(20, 40):
    pkts.append(eth(MAC_X, MAC_G) / IP(src=SCANNER, dst=CLIENT) / TCP(sport=44444, dport=port, flags="S"))

# ARP reply claiming the gateway IP from a different MAC (spoofing indicator)
pkts.append(eth(MAC_X, MAC_C) / ARP(op=2, psrc=GATEWAY, pdst=CLIENT, hwsrc=MAC_X, hwdst=MAC_C))

for i, p in enumerate(pkts):
    p.time = 1_700_000_000 + i * 0.05

out = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_traffic.pcap")
wrpcap(os.path.abspath(out), pkts)
print(f"Wrote {len(pkts)} packets to {os.path.abspath(out)}")
