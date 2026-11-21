"""Save parsed records as JSON or CSV for later analysis."""
import csv
import json

CSV_FIELDS = ["index", "time", "protocol", "src", "sport", "dst", "dport",
              "service", "flags", "length", "ttl", "payload_len", "info", "alerts"]


def write_json(records, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2)


def write_csv(records, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = dict(rec)
            row["alerts"] = "; ".join(rec["alerts"])
            writer.writerow(row)
