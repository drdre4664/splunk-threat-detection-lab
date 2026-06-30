# Incident Report — INC001
## Brute Force Attack Detection

**Date:** 2026-06-03
**Analyst:** Idris Junaid
**Severity:** HIGH
**Status:** Resolved

---

## Executive Summary
A brute force attack was detected against webserver01 originating from external IP 203.0.113.42 
and internal IP 192.168.1.105. The attacker made repeated failed login attempts against multiple 
accounts before successfully authenticating as admin. Post-authentication activity included 
privilege escalation via sudo and lateral movement to 4 additional internal systems.

---

## Timeline of Events

| Time | Event |
|------|-------|
| 08:12:01 | First failed SSH login attempt from 192.168.1.105 |
| 08:12:01–08:12:13 | 7 failed login attempts against admin and root accounts |
| 08:12:15 | Successful login as admin from 192.168.1.105 |
| 08:15:22 | Privilege escalation — admin executed /bin/bash as root via sudo |
| 08:15:25 | Sensitive file access — /etc/shadow read via sudo |
| 08:18:01–08:19:55 | Lateral movement — admin account logged into 4 additional servers |
| 08:22:10–08:22:15 | Second brute force from external IP 203.0.113.42 against oracle account |

---

## Detection Method
Detected using SPL brute force detection rule monitoring for 5+ failed login attempts 
within a 5-minute window across linux_secure logs.

```spl
index=main sourcetype=linux_secure action=failure
| bucket _time span=5m
| stats count AS failed_attempts, values(user) AS targeted_accounts by _time, src_ip
| where failed_attempts >= 5
```

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| External IP | 203.0.113.42 |
| Internal IP | 192.168.1.105 |
| Compromised Account | admin |
| Targeted Accounts | admin, root, oracle |
| Affected Systems | webserver01, dbserver01, appserver01, fileserver01, backupserver01 |

---

## Root Cause
Weak SSH password on admin account with no MFA enforcement. SSH exposed directly 
to internet without IP allowlisting or rate limiting.

---

## Impact Assessment
- Admin account compromised on webserver01
- /etc/shadow file accessed (password hashes potentially exfiltrated)
- Lateral movement to 4 internal servers using compromised credentials
- Potential for further persistence mechanisms installed

---

## Containment Actions Taken
1. Disabled admin account across all affected systems
2. Blocked source IPs 203.0.113.42 and 192.168.1.105 at firewall
3. Forced password reset on all accounts accessed from compromised session
4. Revoked all active SSH sessions

---

## Remediation Recommendations
1. Enforce MFA on all SSH access
2. Implement SSH key-based authentication, disable password auth
3. Restrict SSH access to VPN/jumpbox only
4. Deploy fail2ban or equivalent brute force protection
5. Implement privileged access management (PAM) for sudo usage
6. Review and audit /etc/sudoers across all systems

---

## Lessons Learned

**Detection & Investigation**
- SSH password authentication should never be exposed to the internet — key-based auth only
- Splunk does not always auto-parse fields from raw syslog format; `rex` extraction is required to pull structured fields (user, src_ip, host) from unstructured log lines before stats commands can operate on them
- The attacker IP changed from `192.168.1.105` to `10.0.1.105` mid-attack — the compromised webserver01 was used as a launchpad to pivot into the internal `10.0.x.x` subnet, which is why lateral movement appeared under a different IP
- Internal IPs (192.168.x.x, 10.x.x.x) in an attack are more alarming than external IPs — they indicate the attacker is already inside the network perimeter, where traffic is generally trusted

**Containment & Response**
- Immediate containment = isolate the compromised machine by blocking its IP at the firewall or disabling its network interface — stops further lateral movement instantly
- Lateral movement was possible due to a flat network with no segmentation — all servers could communicate freely with no firewall rules between zones
- Proper network segmentation (DMZ → App zone → DB zone → Backup zone) would have contained the breach to webserver01 alone

**Preventive Controls That Would Have Stopped This**
- MFA on SSH — even with the correct password, a second factor would have blocked the attacker at login
- fail2ban or equivalent — automatically blocks an IP after 3-5 failed attempts, preventing brute force from reaching 14 attempts
- Privileged Access Management (PAM) — would have prevented unrestricted `sudo /bin/bash` and alerted on `/etc/shadow` access
- Shared credentials across systems allowed one compromised account to access all 5 servers — each system should require separate credentials
