import re
import csv
import json
from collections import Counter
from pathlib import Path

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+)'
)

def parse_line(line: str):
    m = LOG_PATTERN.search(line)
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    d["size"] = 0 if d["size"] == "-" else int(d["size"])
    return d

def main(log_path: str):
    log_path = Path(log_path)
    events = []

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            evt = parse_line(line)
            if evt:
                events.append(evt)

    # Stats
    ips = Counter(e["ip"] for e in events)
    paths = Counter(e["path"] for e in events)
    statuses = Counter(e["status"] for e in events)

    summary = {
        "file": str(log_path),
        "total_lines_parsed": len(events),
        "top_ips": ips.most_common(10),
        "top_paths": paths.most_common(10),
        "status_codes": dict(statuses),
    }

    # Output folders
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    # Write CSV
    csv_path = out_dir / "events.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "time", "method", "path", "status", "size"])
        writer.writeheader()
        writer.writerows(events)

    # Write summary JSON
    json_path = out_dir / "summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("✅ Done")
    print(f"- Parsed events: {len(events)}")
    print(f"- CSV: {csv_path}")
    print(f"- Summary: {json_path}")

if __name__ == "__main__":
    # Exemple: python3 parser.py sample_logs/access.log
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 parser.py <path_to_log_file>")
        raise SystemExit(1)
    main(sys.argv[1])
