#!/usr/bin/env python3
"""
log_summary.py - Produce a quick overview of one or more log files.

Shows: line counts, activity by process, security-relevant keyword hits,
and the most frequent IP addresses.

Usage:
    python3 log_summary.py ../logs/sample_auth.log ../logs/sample_syslog.log
"""

import argparse
import re
from collections import Counter

from log_reader import parse_log, read_log

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# keyword -> why it matters
KEYWORDS = {
    "Failed password": "Authentication failure",
    "Invalid user": "Login attempt for non-existent account",
    "Accepted": "Successful authentication",
    "new user": "Account created",
    "add '": "User added to a group",
    "COMMAND=": "Sudo command executed",
    "incorrect password": "Sudo password failures",
    "UFW BLOCK": "Firewall blocked connection",
    "curl": "Possible download via curl",
    "Out of memory": "Resource exhaustion",
}


def summarize(path):
    print("=" * 60)
    print(f" SUMMARY: {path}")
    print("=" * 60)

    lines = list(read_log(path))
    entries = list(parse_log(path))
    print(f"\nTotal lines: {len(lines)}   Parsed: {len(entries)}")

    if entries:
        print(f"Time range : {entries[0]['timestamp']}  ->  {entries[-1]['timestamp']}")
        print(f"Host(s)    : {', '.join(sorted({e['host'] for e in entries}))}")

    print("\nTop processes:")
    for proc, count in Counter(e["process"] for e in entries).most_common(8):
        print(f"    {proc:<12} {count}")

    print("\nSecurity-relevant keyword hits:")
    hits = {k: sum(1 for line in lines if k in line) for k in KEYWORDS}
    for keyword, count in sorted(hits.items(), key=lambda x: -x[1]):
        if count:
            print(f"    {count:>3}  {keyword:<20} ({KEYWORDS[keyword]})")

    ips = Counter(ip for line in lines for ip in IP_RE.findall(line))
    # drop IPs that are just kernel packet fields like DST (keep it simple: top 5)
    print("\nMost frequent IP addresses:")
    for ip, count in ips.most_common(5):
        print(f"    {ip:<18} {count}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Summarize log files.")
    parser.add_argument("logfiles", nargs="+", help="One or more log files")
    args = parser.parse_args()
    for path in args.logfiles:
        summarize(path)


if __name__ == "__main__":
    main()
