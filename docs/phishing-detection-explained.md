# Phishing Detection in Splunk — Explained

This document explains the phishing detection logic in `detection-rules/phishing-detection.spl`
and the reasoning behind each rule. Phishing disruption is about catching brand-impersonation
and credential-harvesting email before, or as soon as, it reaches employees.

---

## The Data: Email Gateway Logs
Every email passing through the secure email gateway produces a log record with fields:

| Field | Meaning |
|-------|---------|
| sender / sender_domain | Who sent it and from what domain |
| display_name | The friendly "From" name shown to the user |
| recipient | Who received it |
| subject | Email subject line |
| spf / dkim / dmarc | Email authentication results (pass/fail/none) |
| num_links / url | Links contained in the body |
| attachment | Attached file, if any |

---

## The 7 Detection Rules

### Rule 1 — Authentication Failures (SPF/DKIM/DMARC)
**Why:** These three protocols verify an email genuinely came from the domain it
claims. Real Wells Fargo mail passes all three. An email claiming to be from a
brand but failing them is almost always spoofed.
- **SPF** — is the sending server authorized to send for this domain?
- **DKIM** — is the message cryptographically signed and untampered?
- **DMARC** — ties SPF+DKIM together and tells receivers what to do on failure.

### Rule 2 — Lookalike / Cousin Domains
**Why:** Attackers register domains that look almost like the real one —
`wellsf4rgo.com`, `wellsfarg0.com`, `wells-fargo-secure.com`. The regex catches
character substitutions (4-for-a, 0-for-o) and hyphenated/added-word variants,
then excludes the legitimate domain.

### Rule 3 — Display Name Spoofing
**Why:** Users see the display name, not the real address. An email showing
"Wells Fargo Security" or the CEO's name but sent from a non-wellsfargo.com
domain is impersonation. Catches CEO-fraud / business email compromise.

### Rule 4 — Suspicious URLs
**Why:** Legitimate mail links to known corporate domains. Links to raw IP
addresses (`http://198.51.100.77/...`) or URL shorteners (`bit.ly`) hide the
true destination and are hallmarks of credential-harvesting pages.

### Rule 5 — Urgency / Credential-Harvesting Language
**Why:** Phishing manufactures urgency — "verify immediately," "account
suspended," "password expires today" — to make the victim act before thinking.

### Rule 6 — Campaign Fan-Out Detection
**Why:** This is the most important rule for **disruption**. One suspicious email
is an event; the same suspicious sender hitting many employees in an hour is an
active campaign. Counting distinct recipients per sender per time window
separates one-offs from campaigns that need immediate blocking.

### Rule 7 — Combined Risk Score
**Why:** No single signal is perfect — legitimate mail occasionally fails SPF,
some real mail is urgent. So instead of binary block/allow, we **score** across
all indicators (auth failures, urgency, IP/shortener URLs, brand impersonation)
and act on the total. This is how enterprise phishing detection actually works:
weighted scoring, not single rules. Verdict tiers: REVIEW / QUARANTINE / BLOCK.

---

## Why Scoring Beats Single Rules
A single rule is either too noisy (blocks legitimate mail) or too loose (misses
phishing). Scoring lets weak signals combine: an email that merely fails SPF
scores low and is reviewed; one that fails all auth AND uses urgency AND
impersonates the brand AND links to an IP scores 100 and is blocked outright.
This mirrors real platforms like Proofpoint and Microsoft Defender for Office 365.

---

## Mapping to MITRE ATT&CK
| Rule | Technique |
|------|-----------|
| Lookalike domains, display spoofing | T1566.002 — Phishing: Spearphishing Link |
| Credential-harvesting URLs | T1056 — Input Capture |
| CEO fraud / BEC | T1534 — Internal Spearphishing |
| Campaign fan-out | T1566 — Phishing |
