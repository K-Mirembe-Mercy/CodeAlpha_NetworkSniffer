"""Console formatting: one-line summaries, verbose view, optional colour."""

COLORS = {"TCP": "36", "UDP": "35", "DNS": "34", "HTTP": "32", "TLS": "33",
          "ICMP": "31", "ARP": "93"}


def paint(text, code, enabled):
    return f"\033[{code}m{text}\033[0m" if enabled and code else text


def _addr(ip, port):
    if ip is None:
        return "?"
    return f"{ip}:{port}" if port is not None else ip


def format_line(rec, color=True):
    proto = paint(f"{rec['protocol']:<5}", COLORS.get(rec["protocol"]), color)
    route = f"{_addr(rec['src'], rec['sport'])} -> {_addr(rec['dst'], rec['dport'])}"
    extra = " ".join(p for p in (f"[{rec['service']}]" if rec["service"] else "",
                                 rec["flags"], rec["info"]) if p)
    line = f"#{rec['index']:<4} {rec['time']} {proto} {route}  {rec['length']}B  {extra}"
    if rec["alerts"]:
        line += paint("  [!]", "91", color)
    return line


def format_verbose(rec, color=True):
    out = [paint(f"--- Packet #{rec['index']} at {rec['time']}  ({rec['length']} bytes) ---", "1", color)]
    if rec["eth_src"]:
        out.append(f"  Ethernet : {rec['eth_src']} -> {rec['eth_dst']}")
    out.append(f"  Network  : {rec['src']} -> {rec['dst']}" + (f"  TTL={rec['ttl']}" if rec["ttl"] is not None else ""))
    out.append(f"  Protocol : {paint(rec['protocol'], COLORS.get(rec['protocol']), color)}"
               + (f"  ports {rec['sport']} -> {rec['dport']}" if rec["sport"] is not None else "")
               + (f"  [{rec['service']}]" if rec["service"] else ""))
    if rec["flags"]:
        out.append(f"  TCP flags: {rec['flags']}")
    if rec["info"]:
        out.append(f"  Info     : {rec['info']}")
    if rec["payload_len"]:
        out.append(f"  Payload  : {rec['payload_len']} bytes | {rec['payload_preview']}")
        if rec["payload_hex"]:
            out.extend("    " + row for row in rec["payload_hex"].splitlines())
    for alert in rec["alerts"]:
        out.append(paint(f"  [!] {alert}", "91", color))
    return "\n".join(out)
