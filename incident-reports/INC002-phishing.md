# Incident Report — INC002
## Phishing Campaign Targeting Employees

**Date:** 2026-06-18
**Analyst:** Idris Junaid
**Severity:** CRITICAL
**Status:** Contained — Campaign Disrupted

---

## Executive Summary
A coordinated phishing campaign impersonating Wells Fargo was detected through
email gateway log analysis in Splunk. The attacker used the lookalike domain
`wells-fargo-secure.com` with a spoofed "Wells Fargo Security" display name to
send credential-harvesting emails to multiple employees within a one-hour window.
All messages failed SPF, DKIM, and DMARC authentication. The campaign was
identified via SPL detection logic and disrupted before any credentials were
confirmed compromised.

---

## Detection Method
Detected by the phishing campaign fan-out rule, which flags messages failing
email authentication that target multiple recipients in a short window:

```spl
index=email sourcetype=email_gateway (spf=fail OR dkim=fail OR dmarc=fail)
| bin _time span=1h
| stats dc(recipient) AS employees_targeted, count AS total_emails,
        values(subject) AS subject by _time, sender_domain
| where employees_targeted >= 2
```

The combined risk-scoring rule independently scored this sender at 100
(DMARC fail + SPF fail + DKIM fail + urgency language + brand impersonation),
returning a verdict of **BLOCK & DISRUPT**.

---

## Timeline of Events

| Time (UTC) | Event |
|------------|-------|
| 08:03:45 | First phishing email from `wells-fargo-secure.com` delivered to employee2 |
| 08:04:02 | Second email — employee3 |
| 08:04:18 | Third email — employee4 |
| 08:35:42 | Fourth email — employee14 |
| 08:55:39 | Fifth email — employee18 |
| 09:05:00 | Splunk fan-out rule triggered — campaign identified |
| 09:10:00 | Sending domain blocked at gateway; URLs submitted for takedown |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Sending domain | wells-fargo-secure.com |
| Spoofed display name | Wells Fargo Security |
| Malicious URL | http://wells-fargo-secure.com/verify-login |
| Subject line | "Urgent: Verify your account immediately" |
| Auth results | SPF=fail, DKIM=fail, DMARC=fail |
| Recipients targeted | employee2, employee3, employee4, employee14, employee18 |

### Related campaigns identified in same window
| Domain | Theme | Display Name |
|--------|-------|--------------|
| wellsfarg0.com | Payroll update | Wells Fargo Payroll |
| wellsfargo-it.net | Password reset (IP-URL) | IT Support |
| wellsf4rgo.com | CEO gift-card fraud | Charlie Scharf |

---

## Root Cause
External attacker registered lookalike domains impersonating Wells Fargo and
launched credential-harvesting campaigns. Messages failed all email
authentication checks but were still delivered, indicating gateway policy was
set to deliver-and-flag rather than reject on DMARC failure.

---

## Containment & Disruption Actions
1. Blocked sending domain `wells-fargo-secure.com` at the email gateway
2. Submitted phishing URL for takedown via brand-protection vendor
3. Quarantined all delivered copies from employee mailboxes
4. Added detection logic to alert in real time on future auth-fail fan-out
5. Notified targeted employees; confirmed none entered credentials

---

## Remediation Recommendations
1. Change gateway DMARC policy from deliver-and-flag to **reject** on failure
2. Deploy the combined phishing risk-score rule as a real-time alert
3. Register/monitor common lookalike domains defensively
4. Targeted phishing-awareness reminder to all employees
5. Implement automated URL takedown workflow (SOAR integration)

---

## Lessons Learned

**Detection Logic**
- DMARC=fail messages should never be delivered to inboxes — gateway policy was set to deliver-and-flag instead of reject, which is a critical misconfiguration
- Campaign fan-out detection (same suspicious sender → multiple recipients in a short window) is the highest-value signal for distinguishing a one-off email from an active campaign requiring immediate disruption
- A risk-scoring approach catches phishing that no single rule would flag alone — individual signals like urgency language or a failed SPF check can appear in legitimate mail; it is the combination of signals that confirms phishing

**On Risk Scoring Weights**
- The scoring weights (DMARC=30, SPF=20, DKIM=15, urgency=20, IP URL=25, display name impersonation=30) are analyst-defined, not industry-mandated — but they are grounded in how dangerous each signal is in practice
- DMARC receives the highest weight because a DMARC failure is the strongest single indicator that an email is forged — it cannot fail on a legitimately sent email
- The verdict thresholds (70=BLOCK, 50=QUARANTINE, 40=REVIEW) require tuning based on observed false positive rates in production — this process is called threshold calibration and is a standard part of detection engineering
- Real enterprise platforms (Proofpoint, Microsoft Defender for Office 365, Mimecast) use the same weighted scoring approach — no single rule, combined signals into tiered verdicts

**Containment & Disruption**
- Detection alone is not enough — the gateway DMARC policy must be set to reject so that authentication failures never reach the inbox in the first place
- Once a campaign is identified via fan-out detection, all delivered copies must be pulled from inboxes immediately — employees who received the email before the block may still click the link
- Defensive domain registration (registering common lookalike variants of your own domain) would have prevented the attacker from using wells-fargo-secure.com and wellsf4rgo.com
