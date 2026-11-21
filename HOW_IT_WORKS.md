# How the sniffer works

## Pipeline
```
network / .pcap  ->  scapy sniff()  ->  parse_packet()  ->  record (dict)
                                                          ├─> TrafficStats.add()  -> alerts + summary
                                                          ├─> display.format_*()  -> console
                                                          └─> exporters           -> JSON / CSV
(raw packets also go to PcapWriter when -w is used)
```
Each stage only knows the **record** format, so you can change one without breaking the others.

## Layers decoded
| Layer | Fields shown |
|---|---|
| Ethernet | source / destination MAC |
| ARP | who-has / is-at, IP to MAC mapping |
| IP (v4/v6) | source, destination, TTL / hop limit |
| TCP | ports, flags (SYN, ACK, FIN...), sequence number, window |
| UDP | ports, length |
| ICMP | type and code (echo-request, echo-reply...) |
| DNS | query or response, record type, name |
| Application | HTTP request/status line and Host, TLS record type, payload preview + hex |

## TCP flags
`SYN` start a connection, `SYN+ACK` accept, `ACK` confirm (the three-way handshake), `PSH` push data, `FIN` close politely, `RST` abort.

## Detections (and their limits)
| Detection | Rule | Limitation |
|---|---|---|
| Cleartext HTTP / FTP / Telnet | HTTP request/status line seen, or port 21/23/110/143 | A non-standard port may be missed |
| Credentials in cleartext | payload contains `password=`, `pwd=`, `Authorization: Basic`... | Keyword match only; the value is **redacted** and never stored |
| Port scan | one source sends bare SYNs to >= N distinct ports of one host | Slow scans and distributed scans can evade it |
| ARP spoofing | an IP address is announced by a new MAC | DHCP changes or failover can cause false alarms |

These are teaching heuristics, not a replacement for an IDS like Snort or Suricata.

## BPF filter cheat sheet
`host 10.0.0.5` · `net 192.168.1.0/24` · `tcp port 80` · `udp port 53` · `not port 22` · `tcp[tcpflags] & tcp-syn != 0` · `icmp`

## Design choices
- **Redaction by default:** a sniffer should not become a password collector.
- **Offline mode:** reproducible demos and tests without root.
- **Standard library only** (besides scapy): easy to install and review.
- **Tests build packets in memory** so they run anywhere.

## Ideas to extend
GeoIP lookup of public IPs, live protocol chart, TLS SNI extraction, DHCP/mDNS decoding, a simple web dashboard.
