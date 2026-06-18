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
- DMARC=fail messages should never be delivered to inboxes — gateway policy gap
- Campaign fan-out detection (same sender → many recipients) is the highest-value
  signal for distinguishing a one-off from an active campaign requiring disruption
- A risk-scoring approach catches phishing that no single rule would flag alone
