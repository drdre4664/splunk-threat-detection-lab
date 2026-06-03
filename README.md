# Splunk Threat Detection Lab

## Overview
A hands-on security detection lab using Splunk to ingest, analyze, and detect threats across authentication, endpoint, and network logs. Covers three real-world attack scenarios with SPL detection rules, threat hunting playbooks, and formal incident reports.

## Attack Scenarios Covered
1. **Brute Force Attack** — Detecting repeated failed authentication attempts
2. **Privilege Escalation** — Identifying unauthorized permission changes
3. **Lateral Movement** — Tracing attacker movement across systems

## Repository Structure
- `detection-rules/` — SPL queries for each attack scenario
- `sample-logs/` — Sample log data used for detection
- `incident-reports/` — Formal incident reports with findings and remediation
- `docs/` — Threat hunting playbooks and methodology

## Tools Used
- Splunk Enterprise / Splunk Cloud
- SPL (Splunk Processing Language)
- Linux auth logs, Windows Event logs, Sysmon

## Skills Demonstrated
- SIEM log ingestion and parsing
- Detection rule engineering
- Threat hunting
- Incident response documentation
- Log correlation across multiple sources

