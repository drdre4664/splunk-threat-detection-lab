# Threat Hunting Playbook

## Overview
This playbook defines the methodology for proactive threat hunting across authentication,
endpoint, and network logs using Splunk SPL queries.

---

## Hunt 1 — Brute Force Detection

**Hypothesis:** An attacker is attempting to gain access by repeatedly guessing credentials.

**Data Sources:** linux_secure, WinEventLog:Security (EventCode 4625)

**SPL Query:**
```spl
index=main sourcetype=linux_secure OR sourcetype=WinEventLog:Security
(action=failure OR EventCode=4625)
| bucket _time span=5m
| stats count AS failed_attempts, values(user) AS targeted_accounts by _time, src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

**What to look for:**
- Same source IP with 5+ failures in 5 minutes
- Multiple usernames targeted from same IP (credential stuffing)
- Failures followed by a successful login (successful brute force)

**Escalate if:**
- Failed attempts followed by successful login
- Source IP is external/unknown
- Targeted account is privileged (admin, root, service account)

---

## Hunt 2 — Privilege Escalation

**Hypothesis:** A user has gained elevated privileges beyond their normal access level.

**Data Sources:** linux_secure (sudo), WinEventLog:Security (EventCode 4728, 4732, 4756)

**SPL Query:**
```spl
index=main sourcetype=linux_secure
(command="sudo" OR command="su")
| stats count AS escalation_count, values(host) AS systems by user, _time
| where escalation_count >= 1
| sort -escalation_count
```

**What to look for:**
- sudo/su usage outside business hours
- Privileged commands run by non-admin accounts
- New users added to admin/sudo groups
- Sensitive file access (/etc/shadow, /etc/passwd)

**Escalate if:**
- Privilege escalation from a compromised or unusual account
- Escalation followed by sensitive data access
- New admin account created unexpectedly

---

## Hunt 3 — Lateral Movement

**Hypothesis:** An attacker is moving through the network using compromised credentials.

**Data Sources:** linux_secure (SSH), WinEventLog:Security (EventCode 4624, 4648)

**SPL Query:**
```spl
index=main sourcetype=linux_secure
command="ssh" OR "Accepted password"
| stats dc(host) AS unique_hosts, values(host) AS accessed_hosts by src_ip, user
| where unique_hosts >= 3
| sort -unique_hosts
```

**What to look for:**
- Same account logging into 3+ systems within short timeframe
- Authentication from unusual source IPs
- Use of PsExec, WMI, or remote PowerShell
- Service accounts authenticating interactively

**Escalate if:**
- Movement toward high-value targets (domain controllers, databases, backup servers)
- Access patterns inconsistent with user's normal behavior
- Use of pass-the-hash or pass-the-ticket techniques

---

## Incident Response Workflow

1. **Detect** — Alert fires from detection rule or analyst identifies anomaly
2. **Triage** — Confirm alert is not a false positive, assess initial severity
3. **Investigate** — Expand scope, identify all affected systems and accounts
4. **Contain** — Isolate affected systems, disable compromised accounts
5. **Eradicate** — Remove malicious artifacts, close attack vectors
6. **Recover** — Restore systems, reset credentials, verify integrity
7. **Document** — Complete incident report with timeline, IOCs, and lessons learned
