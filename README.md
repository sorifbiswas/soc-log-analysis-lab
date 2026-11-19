# SOC Log Analysis Lab

A hands-on lab for learning Security Operations Center (SOC) log analysis. It uses sample Linux logs,
Python scripts, detection rules, and a written investigation report to practice detecting and
documenting an SSH brute-force attack that leads to account compromise.

> All IP addresses are from documentation ranges (RFC 5737). No real systems or data are involved.

## What's inside

```
soc-log-analysis-lab/
├── README.md
├── logs/
│   ├── sample_auth.log            # SSH, sudo, user-management events
│   └── sample_syslog.log          # cron, systemd, kernel/firewall events
├── python/
│   ├── log_reader.py              # read, parse, and filter logs
│   ├── failed_login_analyzer.py   # brute-force and compromise detection
│   └── log_summary.py             # quick statistical overview of logs
├── detection-rules/
│   └── basic-detection-rules.md   # 8 rules + Sigma example, mapped to MITRE ATT&CK
├── notes/
│   ├── linux-logs.md              # log locations, formats, useful commands
│   └── log-analysis-basics.md     # investigation workflow and attack patterns
├── reports/
│   └── sample-investigation.md    # full incident report with timeline
└── screenshots/                   # add screenshots of your tool output here
```

## Quick start

Requires Python 3.8+ and no third-party packages.

```bash
git clone https://github.com/sorifbiswas/soc-log-analysis-lab.git
cd soc-log-analysis-lab/python

# Read and filter a log
python3 log_reader.py ../logs/sample_auth.log --grep "Failed password" --limit 5

# Detect brute force and suspicious successful logins
python3 failed_login_analyzer.py ../logs/sample_auth.log --threshold 5

# Summarize one or more logs
python3 log_summary.py ../logs/sample_auth.log ../logs/sample_syslog.log
```

## Scenario

On 19 Nov at ~14:22 an external IP (`203.0.113.45`) probes the server, brute-forces SSH, and logs in
as `deploy`. The attacker gets a root shell, creates a backdoor `sudo` user (`support`), and sets up
a `curl | bash` payload. Your job is to find it, build the timeline, and write it up.

**Expected analyzer findings:** 12 failed logins from `203.0.113.45`, 7 invalid usernames
overall, and a **HIGH** severity successful login by `deploy` after the failures.

## Skills demonstrated

- Linux authentication and system log analysis
- Parsing logs with Python (regex, `collections.Counter`)
- Writing detection rules and mapping them to MITRE ATT&CK
- Event correlation and incident timeline reconstruction
- Incident reporting and remediation recommendations

## Ideas to extend

- Add time-window detection (e.g. 5+ failures within 5 minutes)
- Export results to CSV or JSON
- Add GeoIP lookups for source IPs
- Parse web server logs (Apache/Nginx) for SQLi/XSS attempts
- Convert the rules to Sigma and test with `sigma-cli`

## License

MIT – free to use for learning.
