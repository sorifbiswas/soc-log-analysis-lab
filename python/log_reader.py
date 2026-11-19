#!/usr/bin/env python3
"""
log_reader.py - Read and parse Linux syslog-style log files.

Usage:
    python3 log_reader.py ../logs/sample_auth.log
    python3 log_reader.py ../logs/sample_auth.log --grep sshd
    python3 log_reader.py ../logs/sample_auth.log --grep "Failed password" --limit 5
"""

import argparse
import re
import sys
from pathlib import Path

# Matches: "Nov 19 08:01:12 ubuntu-srv sshd[1021]: message..."
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<message>.*)$"
)


def read_log(path):
    """Yield raw lines from a log file, stripping trailing newlines."""
    file_path = Path(path)
    if not file_path.is_file():
        sys.exit(f"[!] File not found: {path}")
    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.strip():
                yield line


def parse_line(line):
    """Parse one syslog line into a dict. Returns None if it doesn't match."""
    match = SYSLOG_PATTERN.match(line)
    return match.groupdict() if match else None


def parse_log(path):
    """Yield parsed entries (dicts) for every parseable line in a file."""
    for line in read_log(path):
        entry = parse_line(line)
        if entry:
            yield entry


def main():
    parser = argparse.ArgumentParser(description="Read and filter a log file.")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("--grep", help="Only show lines containing this text (case-insensitive)")
    parser.add_argument("--limit", type=int, help="Maximum number of lines to show")
    args = parser.parse_args()

    shown = 0
    for line in read_log(args.logfile):
        if args.grep and args.grep.lower() not in line.lower():
            continue
        print(line)
        shown += 1
        if args.limit and shown >= args.limit:
            break

    print(f"\n[+] {shown} line(s) displayed", file=sys.stderr)


if __name__ == "__main__":
    main()
