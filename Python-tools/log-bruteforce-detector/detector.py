#!/usr/bin/env python3
"""Automated Log Parser & Brute-Force Detector.

Reads a Linux SSH auth log, finds failed logins, and flags IP addresses
that fail too many times within a short time window.
"""

import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Matches lines like:
# Nov  1 10:15:32 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_line(line, year):
    """Turn one log line into a dict, or return None if it doesn't match."""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    stamp = f"{year} {match['month']} {match['day']} {match['time']}"
    return {
        "time": datetime.strptime(stamp, "%Y %b %d %H:%M:%S"),
        "result": match["result"],
        "user": match["user"],
        "ip": match["ip"],
    }


def parse_log(path):
    """Read the whole file and return a list of parsed events."""
    year = datetime.now().year  # syslog lines don't include the year
    events = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line, year)
            if event:
                events.append(event)
    return events


def find_bruteforce(events, threshold, window_seconds):
    """Return {ip: info} for IPs with `threshold` failures inside the window."""
    failures = defaultdict(list)
    for e in events:
        if e["result"] == "Failed":
            failures[e["ip"]].append(e)

    window = timedelta(seconds=window_seconds)
    flagged = {}
    for ip, fails in failures.items():
        fails.sort(key=lambda e: e["time"])
        start = 0
        for end in range(len(fails)):
            # slide the left edge forward until the window fits
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            if end - start + 1 >= threshold:
                flagged[ip] = {
                    "total_failures": len(fails),
                    "first_seen": fails[0]["time"],
                    "last_seen": fails[-1]["time"],
                    "usernames": sorted({e["user"] for e in fails}),
                }
                break
    return flagged


def find_possible_compromises(events, flagged):
    """Flag IPs that were suspicious AND later logged in successfully."""
    hits = []
    for e in events:
        if e["result"] == "Accepted" and e["ip"] in flagged:
            if e["time"] >= flagged[e["ip"]]["first_seen"]:
                hits.append(e)
    return hits


def print_report(flagged, compromises, threshold, window_seconds):
    print("=" * 60)
    print(" BRUTE-FORCE DETECTION REPORT")
    print(f" Rule: {threshold}+ failed logins within {window_seconds} seconds")
    print("=" * 60)
    if not flagged:
        print("No suspicious IPs found.")
        return
    for ip, info in sorted(flagged.items(), key=lambda x: -x[1]["total_failures"]):
        print(f"\n[!] {ip}")
        print(f"    Total failed attempts : {info['total_failures']}")
        print(f"    First / last seen     : {info['first_seen']} -> {info['last_seen']}")
        print(f"    Usernames tried       : {', '.join(info['usernames'])}")
    if compromises:
        print("\n" + "!" * 60)
        print(" WARNING: suspicious IPs with a SUCCESSFUL login afterwards:")
        for e in compromises:
            print(f"    {e['time']}  user={e['user']}  ip={e['ip']}")
        print("!" * 60)


def write_csv(flagged, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "total_failures", "first_seen", "last_seen", "usernames"])
        for ip, info in flagged.items():
            writer.writerow([ip, info["total_failures"], info["first_seen"],
                             info["last_seen"], ";".join(info["usernames"])])
    print(f"\nCSV saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts in a log file.")
    parser.add_argument("logfile", help="path to the auth log")
    parser.add_argument("--threshold", type=int, default=5, help="failed attempts to trigger an alert (default 5)")
    parser.add_argument("--window", type=int, default=60, help="time window in seconds (default 60)")
    parser.add_argument("--csv", help="optional path to save flagged IPs as CSV")
    args = parser.parse_args()

    events = parse_log(args.logfile)
    print(f"Parsed {len(events)} SSH login events.")
    flagged = find_bruteforce(events, args.threshold, args.window)
    compromises = find_possible_compromises(events, flagged)
    print_report(flagged, compromises, args.threshold, args.window)
    if args.csv:
        write_csv(flagged, args.csv)


if __name__ == "__main__":
    main()
