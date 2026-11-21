"""Traffic statistics plus two simple, explainable detections.

* SYN scan heuristic: one source sends bare SYNs to many different ports.
* ARP change heuristic: an IP address suddenly maps to a different MAC
  (a classic sign of ARP spoofing / man-in-the-middle).
"""
from collections import Counter, defaultdict


class TrafficStats:
    def __init__(self, scan_threshold=15):
        self.scan_threshold = scan_threshold
        self.total = 0
        self.total_bytes = 0
        self.protocols = Counter()
        self.talkers = Counter()
        self.conversations = Counter()
        self.alert_counts = Counter()
        self._syn_ports = defaultdict(set)
        self._scan_reported = set()
        self._arp_table = {}

    def add(self, rec):
        """Update counters with a record. Returns NEW alert strings only."""
        self.total += 1
        self.total_bytes += rec["length"]
        self.protocols[rec["protocol"]] += 1
        if rec["src"]:
            self.talkers[rec["src"]] += 1
            if rec["dst"]:
                self.conversations[(rec["src"], rec["dst"])] += 1

        for alert in rec["alerts"]:
            self.alert_counts[alert] += 1

        new_alerts = []

        # SYN without ACK = a connection attempt. Many distinct ports = scan.
        if rec["protocol"] == "TCP" and rec["flags"] == "SYN":
            key = (rec["src"], rec["dst"])
            ports = self._syn_ports[key]
            ports.add(rec["dport"])
            if len(ports) >= self.scan_threshold and key not in self._scan_reported:
                self._scan_reported.add(key)
                msg = (f"Possible port scan: {rec['src']} sent SYNs to "
                       f"{len(ports)} different ports on {rec['dst']}")
                self.alert_counts[msg] += 1
                new_alerts.append(msg)

        # ARP: remember IP->MAC; a change is suspicious.
        if rec["arp_ip"]:
            known = self._arp_table.get(rec["arp_ip"])
            if known and known != rec["arp_mac"]:
                msg = (f"ARP change: {rec['arp_ip']} moved from {known} to "
                       f"{rec['arp_mac']} (possible ARP spoofing)")
                self.alert_counts[msg] += 1
                new_alerts.append(msg)
            self._arp_table[rec["arp_ip"]] = rec["arp_mac"]

        return new_alerts

    def summary(self):
        lines = ["", "=" * 60, "CAPTURE SUMMARY", "=" * 60,
                 f"Packets: {self.total}    Bytes: {self.total_bytes}", "",
                 "Protocols:"]
        for name, n in self.protocols.most_common():
            pct = 100 * n / self.total if self.total else 0
            lines.append(f"  {name:<10} {n:>6}  {pct:5.1f}%  {'#' * int(pct // 4)}")
        if self.talkers:
            lines += ["", "Top talkers (packets sent):"]
            lines += [f"  {ip:<40} {n}" for ip, n in self.talkers.most_common(5)]
        if self.conversations:
            lines += ["", "Top conversations:"]
            lines += [f"  {a} -> {b}  ({n})" for (a, b), n in self.conversations.most_common(5)]
        if self.alert_counts:
            lines += ["", "Security observations:"]
            lines += [f"  [!] {msg}  x{n}" for msg, n in self.alert_counts.most_common()]
        return "\n".join(lines)
