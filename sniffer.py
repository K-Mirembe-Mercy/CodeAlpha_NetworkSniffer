#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Capture live traffic (or replay a .pcap file), decode every layer, show
source/destination IPs, protocols, ports and payloads, and flag risky
behaviour. Use ONLY on networks you own or are authorised to monitor.
Live capture needs root/Administrator; reading a .pcap (-r) does not.
"""
import argparse
import sys

from snifferlib import __version__
from snifferlib.display import format_line, format_verbose, paint
from snifferlib.exporters import write_csv, write_json
from snifferlib.parser import parse_packet
from snifferlib.stats import TrafficStats

try:
    from scapy.all import PcapWriter, get_if_list, sniff
except ImportError:
    sys.exit("scapy is not installed. Run: pip install -r requirements.txt")


def build_parser():
    p = argparse.ArgumentParser(
        description="Basic network sniffer (educational).",
        epilog='Examples:  sudo python3 sniffer.py -c 20 | '
               'python3 sniffer.py -r samples/sample_traffic.pcap -v | '
               'sudo python3 sniffer.py -f "tcp port 80" --json out.json')
    p.add_argument("-i", "--iface", help="interface to sniff (default: auto)")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    p.add_argument("-t", "--timeout", type=int, default=None, help="stop after N seconds")
    p.add_argument("-f", "--filter", default=None, help='BPF filter, e.g. "udp port 53"')
    p.add_argument("-r", "--read", metavar="PCAP", help="read packets from a pcap file instead of the network")
    p.add_argument("-v", "--verbose", action="store_true", help="multi-line output with hex dump")
    p.add_argument("-q", "--quiet", action="store_true", help="no per-packet output, summary only")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("-w", "--pcap", metavar="FILE", help="save raw packets to a pcap file")
    p.add_argument("--json", metavar="FILE", help="export parsed packets as JSON")
    p.add_argument("--csv", metavar="FILE", help="export parsed packets as CSV")
    p.add_argument("--scan-threshold", type=int, default=15,
                   help="distinct ports before a SYN scan alert (default 15)")
    p.add_argument("--list-interfaces", action="store_true", help="list interfaces and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_interfaces:
        print("\n".join(get_if_list()))
        return 0

    color = not args.no_color and sys.stdout.isatty()
    stats = TrafficStats(scan_threshold=args.scan_threshold)
    records = []
    writer = PcapWriter(args.pcap, sync=True) if args.pcap else None
    keep_records = bool(args.json or args.csv)
    counter = [0]

    def on_packet(pkt):
        counter[0] += 1
        rec = parse_packet(pkt, counter[0])
        new_alerts = stats.add(rec)
        if keep_records:
            records.append(rec)
        if writer:
            writer.write(pkt)
        if not args.quiet:
            print(format_verbose(rec, color) if args.verbose else format_line(rec, color))
        for msg in new_alerts:
            print(paint(f"      [!] ALERT: {msg}", "91", color))

    source = f"file {args.read}" if args.read else f"{args.iface or 'default interface'}"
    print(f"Sniffer {__version__} | source: {source} | filter: {args.filter or 'none'} | Ctrl+C to stop")

    kwargs = {"offline": args.read} if args.read else {"iface": args.iface, "timeout": args.timeout}
    try:
        sniff(prn=on_packet, store=False, count=args.count, filter=args.filter, **kwargs)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied: run with sudo (Linux/macOS) or as Administrator (Windows).", file=sys.stderr)
        return 1
    except ImportError as exc:
        print(f"BPF filters need libpcap: {exc}\nInstall it (Linux: apt install libpcap-dev tcpdump, "
              "macOS: preinstalled, Windows: Npcap) or run without -f.", file=sys.stderr)
        return 1
    except (OSError, FileNotFoundError) as exc:
        print(f"Capture error: {exc}\nOn Windows install Npcap; check the interface name with --list-interfaces.",
              file=sys.stderr)
        return 1
    finally:
        if writer:
            writer.close()

    print(stats.summary())
    if args.json:
        write_json(records, args.json)
        print(f"\nSaved JSON: {args.json}")
    if args.csv:
        write_csv(records, args.csv)
        print(f"Saved CSV:  {args.csv}")
    if args.pcap:
        print(f"Saved pcap: {args.pcap}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
