"""Packet parsing: turns a scapy packet into a plain dict (a "record").

Keeping parsing separate from capturing and display makes every part easy to
test and lets the same records feed the console, statistics and exporters.
"""
import re
from datetime import datetime

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, IPv6, Raw

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    443: "HTTPS", 465: "SMTPS", 587: "SMTP-sub", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-alt",
}
FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
              "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request",
              11: "time-exceeded"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ")
CREDENTIAL_HINTS = (b"password=", b"passwd=", b"pwd=", b"pass=",
                    b"authorization: basic")
CLEARTEXT_SERVICES = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP"}
HOST_RE = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.IGNORECASE)


def printable(data, limit=48):
    """ASCII preview of bytes; non-printable bytes become '.'."""
    chunk = data[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return text + ("..." if len(data) > limit else "")


def hexdump(data, limit=64):
    """Classic 16-bytes-per-row hex dump of the first `limit` bytes."""
    rows = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:04x}  {hexpart:<47}  {asciipart}")
    return "\n".join(rows)


def _new_record(pkt, index):
    return {
        "index": index,
        "time": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
        "length": len(pkt),
        "eth_src": None, "eth_dst": None,
        "src": None, "dst": None, "ttl": None,
        "protocol": "OTHER", "sport": None, "dport": None,
        "service": "", "flags": "", "info": "",
        "payload_len": 0, "payload_preview": "", "payload_hex": "",
        "arp_ip": None, "arp_mac": None,
        "alerts": [],
    }


def _inspect_payload(rec, data):
    """Look inside application data: HTTP, TLS, cleartext credentials."""
    rec["payload_len"] = len(data)
    rec["payload_preview"] = printable(data)
    rec["payload_hex"] = hexdump(data)

    if data.startswith(HTTP_METHODS):
        line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        host = HOST_RE.search(data)
        rec["protocol"] = "HTTP"
        rec["info"] = line[:80] + (f"  (Host: {host.group(1).decode(errors='replace')})" if host else "")
        rec["alerts"].append("Unencrypted HTTP traffic: anyone on the path can read it")
    elif data.startswith(b"HTTP/"):
        rec["protocol"] = "HTTP"
        rec["info"] = data.split(b"\r\n", 1)[0].decode(errors="replace")[:80]
        rec["alerts"].append("Unencrypted HTTP traffic: anyone on the path can read it")
    elif len(data) > 2 and data[0] == 0x16 and data[1] == 0x03:
        rec["protocol"] = "TLS"
        rec["info"] = "TLS handshake (encrypted session starting)"
    elif len(data) > 2 and data[0] == 0x17 and data[1] == 0x03:
        rec["protocol"] = "TLS"
        rec["info"] = "TLS application data (encrypted)"

    lowered = data.lower()
    if any(hint in lowered for hint in CREDENTIAL_HINTS):
        rec["alerts"].append("Possible credentials sent in cleartext")
        # Never display or store secrets: redact the preview and hex dump.
        rec["payload_preview"] = "[redacted: possible credentials]"
        rec["payload_hex"] = ""


def parse_packet(pkt, index=0):
    """Convert a scapy packet into a flat, JSON-friendly dict."""
    rec = _new_record(pkt, index)

    if pkt.haslayer(Ether):
        rec["eth_src"], rec["eth_dst"] = pkt[Ether].src, pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec.update(protocol="ARP", src=arp.psrc, dst=arp.pdst)
        if arp.op == 1:
            rec["info"] = f"who has {arp.pdst}? tell {arp.psrc}"
        else:
            rec["info"] = f"{arp.psrc} is at {arp.hwsrc}"
            rec["arp_ip"], rec["arp_mac"] = arp.psrc, arp.hwsrc
        return rec

    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.update(src=ip.src, dst=ip.dst, ttl=ip.ttl)
        proto_num = ip.proto
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.update(src=ip6.src, dst=ip6.dst, ttl=ip6.hlim)
        proto_num = ip6.nh
    else:
        rec["info"] = pkt.summary()
        return rec

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.update(protocol="TCP", sport=tcp.sport, dport=tcp.dport)
        rec["flags"] = "+".join(FLAG_NAMES[c] for c in str(tcp.flags) if c in FLAG_NAMES)
        rec["info"] = f"seq={tcp.seq} win={tcp.window}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.update(protocol="UDP", sport=udp.sport, dport=udp.dport)
        rec["info"] = f"len={udp.len}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        rec["protocol"] = "ICMP"
        rec["info"] = ICMP_TYPES.get(icmp.type, f"type {icmp.type}") + f" code={icmp.code}"
    else:
        rec["protocol"] = f"IP/{proto_num}"

    rec["service"] = PORT_NAMES.get(rec["dport"]) or PORT_NAMES.get(rec["sport"]) or ""

    if pkt.haslayer(DNSQR):
        dns = pkt[DNS]
        q = pkt[DNSQR]
        name = q.qname.decode(errors="replace").rstrip(".")
        qtype = DNS_TYPES.get(q.qtype, str(q.qtype))
        rec["protocol"] = "DNS"
        rec["info"] = f"{'query' if dns.qr == 0 else 'response'} {qtype} {name}"

    if pkt.haslayer(Raw):
        _inspect_payload(rec, bytes(pkt[Raw].load))

    for port in (rec["dport"], rec["sport"]):
        if port in CLEARTEXT_SERVICES:
            rec["alerts"].append(f"{CLEARTEXT_SERVICES[port]} is usually unencrypted: prefer a TLS variant")
            break

    return rec
