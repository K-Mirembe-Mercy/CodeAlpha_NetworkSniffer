# CodeAlpha_NetworkSniffer

A network packet sniffer in Python, built with [scapy](https://scapy.net/) for the **CodeAlpha Cyber Security Internship (Task 1)**.
It captures live traffic or replays a `.pcap` file, decodes every layer, shows source/destination IPs, protocols, ports and payloads, and **flags risky behaviour** (cleartext HTTP, credentials in plain text, port scans, ARP spoofing).

> **Use only on networks you own or have written permission to monitor.** Capturing other people's traffic is illegal in most countries.

## Features
- Decodes **Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP and TLS**
- Shows IPs, ports, service names, TCP flags, TTL, DNS queries, HTTP request lines and Host headers
- Payload preview and **hex dump** (`-v`)
- **Credential redaction:** secrets such as `password=...` are detected but never displayed or exported
- **Detections:** unencrypted HTTP/FTP/Telnet, SYN port scans, ARP spoofing
- Statistics: protocol breakdown, top talkers, top conversations
- **Offline mode** (`-r file.pcap`): works without root, so it is ideal for demos
- Export to **pcap, JSON and CSV**
- BPF filters, interface selection, packet count and timeout limits, colour output
- 14 unit tests that run without network access or root

## Project structure
```
CodeAlpha_NetworkSniffer/
├── sniffer.py                    # command-line entry point
├── snifferlib/
│   ├── parser.py                 # packet -> record (layers, HTTP/TLS/DNS, redaction)
│   ├── stats.py                  # counters + scan/ARP-spoof detection
│   ├── display.py                # coloured one-line and verbose output
│   └── exporters.py              # JSON / CSV writers
├── tests/test_sniffer.py         # unit tests (unittest)
├── examples/generate_sample_pcap.py  # builds the fictional demo capture
├── samples/sample_traffic.pcap   # demo capture (fictional packets)
├── docs/
│   ├── HOW_IT_WORKS.md           # architecture + networking concepts
│   ├── DEMO_SCRIPT.md            # script for the LinkedIn video
│   └── sample_output.txt         # real output on the demo capture
├── requirements.txt
├── LICENSE
└── .gitignore
```

## Installation
```bash
git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```
Requirements: Python 3.8+. **Windows:** install [Npcap](https://npcap.com). **Linux:** `sudo apt install libpcap-dev tcpdump` (needed for `-f` filters).

## Usage
```bash
# Try it immediately, no root needed
python3 sniffer.py -r samples/sample_traffic.pcap
python3 sniffer.py -r samples/sample_traffic.pcap -v        # verbose with hex dump

# Live capture (needs root / Administrator)
sudo python3 sniffer.py                       # until Ctrl+C
sudo python3 sniffer.py -c 50                 # 50 packets
sudo python3 sniffer.py -i wlan0 -t 30        # 30 seconds on wlan0
sudo python3 sniffer.py -f "udp port 53"      # DNS only (BPF filter)
sudo python3 sniffer.py -f "host 192.168.1.5" -w capture.pcap --json out.json --csv out.csv
python3 sniffer.py --list-interfaces
```
| Option | Meaning |
|---|---|
| `-i`, `--iface` | interface to sniff |
| `-c`, `--count` | stop after N packets |
| `-t`, `--timeout` | stop after N seconds |
| `-f`, `--filter` | BPF filter (`tcp port 80`, `host 10.0.0.1`...) |
| `-r`, `--read` | read a pcap instead of live traffic |
| `-v`, `-q` | verbose with hex dump / summary only |
| `-w`, `--json`, `--csv` | export raw pcap / parsed JSON / CSV |
| `--scan-threshold N` | distinct ports before a port-scan alert (default 15) |
| `--no-color` | disable colours |

## Sample output
Real output from `python3 sniffer.py -r samples/sample_traffic.pcap` (fictional demo traffic):
```
#3    22:13:20.100 DNS   192.0.2.10:40001 -> 192.0.2.53:53  71B  [DNS] query A example.com
#7    22:13:20.300 TCP   192.0.2.10:51000 -> 198.51.100.20:80  54B  [HTTP] SYN seq=100 win=8192
#10   22:13:20.450 HTTP  192.0.2.10:51000 -> 198.51.100.20:80  119B  [HTTP] PSH+ACK GET /index.html HTTP/1.1  (Host: example.com)  [!]
#13   22:13:20.600 TLS   192.0.2.10:51002 -> 198.51.100.20:443  63B  [HTTPS] PSH+ACK TLS handshake (encrypted session starting)

Security observations:
  [!] Unencrypted HTTP traffic: anyone on the path can read it  x3
  [!] Possible credentials sent in cleartext  x1
  [!] Possible port scan: 203.0.113.99 sent SYNs to 15 different ports on 192.0.2.10  x1
  [!] ARP change: 192.0.2.1 moved from aa:aa:aa:aa:aa:01 to de:ad:be:ef:00:99 (possible ARP spoofing)  x1
```
Full output: [`docs/sample_output.txt`](docs/sample_output.txt).

## Tests
```bash
python3 -m unittest discover -s tests -v
```

## What I learned
- Packets are nested layers: Ethernet > IP > TCP/UDP > application data.
- The TCP handshake (SYN, SYN+ACK, ACK) is visible in the flags.
- HTTP is readable by anyone on the path, while TLS payloads are not. That is why HTTPS matters.
- Port scans and ARP spoofing leave simple, detectable patterns in traffic.
- Good tools separate capture, parsing, display and export, which also makes them testable.

## Troubleshooting
| Problem | Fix |
|---|---|
| `Permission denied` | run with `sudo` / as Administrator, or use `-r` with a pcap |
| No interfaces / capture error (Windows) | install Npcap, then check `--list-interfaces` |
| `BPF filters need libpcap` | install libpcap (see Installation) or drop `-f` |
| Sees only my own traffic | normal on switched/Wi-Fi networks; the sniffer sees what your NIC receives |

## License
MIT, see [LICENSE](LICENSE). Replace `<Your Name>` in the license file.
