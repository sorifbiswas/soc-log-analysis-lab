#!/usr/bin/env python3
"""
failed_login_analyzer.py - Detect brute-force SSH activity in an auth log.

Detects:
  * Source IPs with failed logins at or above a threshold
  * Usernames targeted (and which of them don't exist on the system)
  * Successful logins from an IP that previously failed (possible compromise)

Usage:
    python3 failed_login_analyzer.py ../logs/sample_auth.log
    python3 failed_login_analyzer.py ../logs/sample_auth.log --threshold 5
"""

import argparse
import re
from collections import Counter, defaultdict

from log_reader import read_log

FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)


def analyze(path):
    failed_by_ip = Counter()
    users_by_ip = defaultdict(Counter)
    invalid_users = Counter()
    first_failure = {}      # ip -> timestamp of first failure
    successes = []          # (timestamp, user, ip, method)

    for line in read_log(path):
        timestamp = line[:15]

        m = FAILED_RE.search(line)
        if m:
            ip, user = m["ip"], m["user"]
            failed_by_ip[ip] += 1
            users_by_ip[ip][user] += 1
            first_failure.setdefault(ip, timestamp)
            if m["invalid"]:
                invalid_users[user] += 1
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            successes.append((timestamp, m["user"], m["ip"], m["method"]))

    return failed_by_ip, users_by_ip, invalid_users, first_failure, successes


def main():
    parser = argparse.ArgumentParser(description="Analyze failed SSH logins.")
    parser.add_argument("logfile", help="Path to auth.log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts needed to flag an IP (default: 5)")
    args = parser.parse_args()

    failed_by_ip, users_by_ip, invalid_users, first_failure, successes = analyze(args.logfile)

    print("=" * 60)
    print(" FAILED LOGIN ANALYSIS")
    print("=" * 60)

    print("\n[1] Failed attempts per source IP")
    for ip, count in failed_by_ip.most_common():
        flag = "  <-- SUSPICIOUS" if count >= args.threshold else ""
        print(f"    {ip:<18} {count:>3} failures{flag}")

    print(f"\n[2] Usernames targeted by flagged IPs (threshold >= {args.threshold})")
    for ip, count in failed_by_ip.most_common():
        if count >= args.threshold:
            users = ", ".join(f"{u}({n})" for u, n in users_by_ip[ip].most_common())
            print(f"    {ip}: {users}")

    print("\n[3] Non-existent ('invalid') usernames attempted")
    for user, count in invalid_users.most_common():
        print(f"    {user:<12} {count}")

    print("\n[4] Successful logins from IPs that previously failed")
    found = False
    for timestamp, user, ip, method in successes:
        if failed_by_ip.get(ip, 0) >= 1:
            severity = "HIGH" if failed_by_ip[ip] >= args.threshold else "LOW"
            print(f"    [{severity}] {timestamp}  user={user}  ip={ip}  method={method}  "
                  f"(prior failures: {failed_by_ip[ip]}, first at {first_failure[ip]})")
            found = True
    if not found:
        print("    None found.")

    print()


if __name__ == "__main__":
    main()
