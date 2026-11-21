"""Offline tests: build packets with scapy, no network or root needed.
Run:  python3 -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw  # noqa: E402

from snifferlib.parser import hexdump, parse_packet, printable  # noqa: E402
from snifferlib.stats import TrafficStats  # noqa: E402


def tcp(flags="S", dport=443, payload=None, src="10.0.0.1", dst="10.0.0.2"):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags=flags)
    return p / Raw(payload) if payload else p


class ParserTests(unittest.TestCase):
    def test_tcp_syn(self):
        r = parse_packet(tcp("S"), 1)
        self.assertEqual((r["protocol"], r["flags"], r["service"]), ("TCP", "SYN", "HTTPS"))
        self.assertEqual((r["src"], r["dst"], r["dport"]), ("10.0.0.1", "10.0.0.2", 443))

    def test_syn_ack_flags(self):
        self.assertEqual(parse_packet(tcp("SA"))["flags"], "SYN+ACK")

    def test_dns_query(self):
        p = Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        r = parse_packet(p)
        self.assertEqual(r["protocol"], "DNS")
        self.assertIn("example.com", r["info"])

    def test_http_request_flagged(self):
        r = parse_packet(tcp("PA", 80, b"GET /a HTTP/1.1\r\nHost: x.org\r\n\r\n"))
        self.assertEqual(r["protocol"], "HTTP")
        self.assertIn("x.org", r["info"])
        self.assertTrue(any("Unencrypted" in a for a in r["alerts"]))

    def test_credentials_are_redacted(self):
        r = parse_packet(tcp("PA", 80, b"POST /l HTTP/1.1\r\n\r\nuser=a&password=hunter2"))
        self.assertNotIn("hunter2", r["payload_preview"])
        self.assertEqual(r["payload_hex"], "")
        self.assertTrue(any("credentials" in a for a in r["alerts"]))

    def test_tls_detected(self):
        self.assertEqual(parse_packet(tcp("PA", 443, b"\x16\x03\x01\x00\x05abcde"))["protocol"], "TLS")

    def test_icmp_echo(self):
        r = parse_packet(Ether() / IP() / ICMP(type=8))
        self.assertEqual(r["protocol"], "ICMP")
        self.assertIn("echo-request", r["info"])

    def test_arp_reply(self):
        r = parse_packet(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:01"))
        self.assertEqual((r["protocol"], r["arp_ip"], r["arp_mac"]), ("ARP", "10.0.0.1", "aa:aa:aa:aa:aa:01"))

    def test_cleartext_telnet_alert(self):
        self.assertTrue(any("Telnet" in a for a in parse_packet(tcp("S", 23))["alerts"]))

    def test_helpers(self):
        self.assertEqual(printable(b"hi\x00!"), "hi.!")
        self.assertTrue(hexdump(b"ABC").startswith("0000  41 42 43"))


class StatsTests(unittest.TestCase):
    def test_port_scan_alert_fires_once(self):
        s, fired = TrafficStats(scan_threshold=15), []
        for port in range(1, 21):
            fired += s.add(parse_packet(tcp("S", port, src="9.9.9.9")))
        self.assertEqual(len(fired), 1)
        self.assertIn("port scan", fired[0])

    def test_normal_traffic_no_scan_alert(self):
        s = TrafficStats(scan_threshold=15)
        for _ in range(30):
            self.assertEqual(s.add(parse_packet(tcp("S", 443))), [])

    def test_arp_spoof_alert(self):
        s = TrafficStats()
        mk = lambda mac: parse_packet(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc=mac))
        self.assertEqual(s.add(mk("aa:aa:aa:aa:aa:01")), [])
        self.assertIn("ARP change", s.add(mk("de:ad:be:ef:00:99"))[0])

    def test_counters(self):
        s = TrafficStats()
        s.add(parse_packet(tcp("S")))
        s.add(parse_packet(tcp("A")))
        self.assertEqual((s.total, s.protocols["TCP"]), (2, 2))


if __name__ == "__main__":
    unittest.main()
