# Splunk Threat Detection Lab

## Overview
A hands-on security detection lab using Splunk to ingest, analyze, and detect threats
across email, authentication, endpoint, and network logs. Covers real-world attack
scenarios with SPL detection rules, a phishing-disruption module, threat hunting
playbooks, and formal incident reports.

## Detection Scenarios Covered

### Phishing Disruption (email security)
- Email authentication failure detection (SPF / DKIM / DMARC)
- Lookalike / cousin domain impersonation
- Display-name spoofing & CEO fraud (BEC)
- Suspicious URLs (IP-address links, URL shorteners)
- Credential-harvesting / urgency language
- Phishing **campaign fan-out** detection
- Combined **risk-scoring** model (REVIEW / QUARANTINE / BLOCK)

### Endpoint & Identity Threats
- Brute force authentication attacks
- Privilege escalation
- Lateral movement

## Repository Structure
- `detection-rules/` — SPL queries for each detection scenario
- `sample-logs/` — Sample log data (email gateway + auth logs)
- `incident-reports/` — Formal incident reports with findings and remediation
- `docs/` — Detection logic explained + threat hunting playbook

## Tools Used
- Splunk Enterprise (run via Docker)
- SPL (Splunk Processing Language)
- Email gateway logs, Linux auth logs, Windows Event logs, Sysmon

## Skills Demonstrated
- Phishing detection & disruption logic engineering
- SIEM log ingestion and parsing
- Detection rule engineering (regex, scoring models)
- Email authentication analysis (SPF/DKIM/DMARC)
- Threat hunting & campaign identification
- Incident response documentation
- Log correlation across multiple sources
- MITRE ATT&CK mapping

## How to Run (Splunk in Docker)
```bash
# Start Splunk
docker run -d -p 8000:8000 -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='Splunk123!' --name splunk splunk/splunk:latest

# Open http://localhost:8000  (admin / Splunk123!)
# Settings > Add Data > Upload > select a file from sample-logs/
# Set sourcetype, then run queries from detection-rules/
```

## Lessons Learned

### Phishing Detection (INC002)
- DMARC=fail emails should never reach the inbox — the gateway policy must be set to **reject**, not deliver-and-flag
- **Campaign fan-out detection** is the highest-value signal for disruption — one suspicious email is an event, the same sender hitting 5+ employees in an hour is an active campaign requiring immediate blocking
- **Risk scoring beats single rules** — individual signals like urgency language or a failed SPF check appear in legitimate mail too; it is the combination of signals that confirms phishing with confidence
- Scoring weights are analyst-defined but grounded in industry practice — DMARC gets the highest weight (30pts) because it is the strongest single indicator of a forged email; thresholds require tuning based on false positive rates in production (called threshold calibration)
- Real enterprise platforms (Proofpoint, Microsoft Defender for Office 365) use the same weighted scoring approach

### Brute Force & Lateral Movement (INC001)
- Splunk does not always auto-parse fields from raw syslog — `rex` extraction is required to pull structured fields (user, src_ip, host) from unstructured log lines before `stats` commands can operate on them
- The attacker IP changed from `192.168.1.105` to `10.0.1.105` mid-attack — the compromised `webserver01` was used as a launchpad to pivot into the internal subnet; lateral movement does not always come from the same IP as the initial breach
- **Internal IPs in an attack are more alarming than external ones** — they are already inside the network perimeter where traffic is generally trusted and harder to block without disrupting legitimate users
- **Containment** (isolating the compromised machine immediately) and **network segmentation** (preventive zone isolation) are two different controls — containment stops active bleeding, segmentation prevents it from happening in the first place
- A flat network with no segmentation allowed the attacker to reach 4 additional servers with zero resistance — proper zone isolation (DMZ → App → DB → Backup) would have contained the breach to one server
- MFA on SSH would have blocked the attacker even after the password was guessed; fail2ban would have blocked the IP before 14 attempts were reached
