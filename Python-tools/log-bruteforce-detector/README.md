# Automated Log Parser & Brute-Force Detector

A beginner-friendly cybersecurity tool that reads an SSH authentication log and flags IP addresses showing brute-force behavior.

## What it does
- Parses SSH log lines using Regular Expressions
- Counts failed logins per IP inside a sliding time window
- Lists the usernames each suspicious IP tried
- Warns if a suspicious IP later logged in successfully
- Optionally exports results to CSV

## Usage
```bash
python detector.py sample_auth.log
python detector.py sample_auth.log --threshold 5 --window 60 --csv report.csv
```

Requires Python 3.8+. No external libraries.

## How detection works
An IP is flagged when it makes `--threshold` failed attempts within `--window` seconds.
Defaults: 5 failures in 60 seconds.

## Ideas for future improvements
- Support Apache/Nginx access logs
- Look up IP geolocation
- Auto-generate firewall block rules
- Add unit tests with `pytest`

## Disclaimer
For educational and defensive use on logs you own or are authorized to analyze.
