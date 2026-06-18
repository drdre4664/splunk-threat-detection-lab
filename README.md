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
