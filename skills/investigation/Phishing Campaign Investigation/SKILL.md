---
name: Phishing Campaign Investigation
description: |-
  Investigate an escalated phishing alert from one reported or detected lure
  to full campaign scope. Finds every recipient, reconstructs who clicked or
  submitted credentials, attributes the sender infrastructure, and checks for
  post-compromise follow-through before returning a verdict with the affected-
  user scope and containment actions.
type: investigation
version: 1.2.1
metadata:
  author: logsmith
  labels:
    - email
    - phishing
    - identity
    - account-takeover
---

# Phishing Campaign Investigation

Runs on alerts escalated by triage (see `application-delivered-threat`): a
message was reported or detected as a phishing lure. Triage established the
single message is malicious; investigation establishes how far the campaign
reached and who fell for it. The question is not "was this phishing" — it
was — but "who else got it, who acted on it, and are any accounts now
compromised."

## Inputs

- The escalated alert (the lure: sender, subject, URLs/attachments,
  delivery time) and the triage report.
- Mail-gateway and message-trace logs across all mailboxes, URL-click
  telemetry (safe-links or proxy), sign-in logs, and endpoint telemetry for
  any attachment payload.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Campaign scope — signal A

Pivot from the one lure to every related message: same sender, sending
infrastructure, subject pattern, URL, or attachment hash across all
mailboxes. **Signal A fires** when the lure is one of many — establishing a
campaign and the full recipient list — and records how many messages were
delivered versus quarantined.

### 2. Sender attribution — signal B

Attribute the sending infrastructure: sender domain age and reputation,
SPF/DKIM/DMARC results, originating IP/ASN, and whether the URLs point to a
credential-harvesting page or known-malicious infrastructure. **Signal B
fires** on a spoofed or lookalike domain, failed authentication passed off
as internal, or a landing page confirmed to harvest credentials.

### 3. User interaction — signal C

For every delivered recipient, determine who *acted*: clicked the URL,
reached the landing page, submitted credentials, or opened the attachment.
**Signal C fires** for any recipient who submitted credentials or executed
an attachment — this is the line between "received" and "at risk" and drives
the real scope.

### 4. Post-compromise follow-through — signal D

For users who submitted or executed, check for takeover: a subsequent
sign-in from unfamiliar infrastructure, an MFA registration, an inbox rule,
or payload execution on the endpoint. **Signal D fires** when interaction is
followed by attacker activity — turning at-risk accounts into confirmed
compromises.

## Verdict rule

- **malicious:** signal A or B confirms the campaign is real (it always is,
  post-triage); the verdict's weight is in scope. Any signal D makes it a
  confirmed-compromise incident. Signal C with no D is a credential-exposure
  incident.
- **suspicious:** delivery confirmed but interaction (C) can't be
  established from available telemetry, so exposure is possible but unproven.
- **inconclusive:** message-trace or click telemetry is missing, so scope
  and interaction can't be reconstructed.
- **benign:** investigation shows the reported message was a false positive
  — a legitimate sender misjudged by triage, authenticated and reputable,
  with a landing page that is not harvesting — and no user was put at risk.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it, and an explicit affected-user scope.

### Recommended actions
When not benign: purge all campaign messages from every mailbox, block the
sender/domain/URLs, force password reset and session revocation for every
credential-submitter, drive containment for any confirmed-compromised
account (see `mfa-deepdive` and the account-takeover flow), and warn the
recipient population. Prioritize the credential-submitters from step 3.

### Evidence
The full campaign message set and recipient list (delivered vs quarantined),
sender attribution (domain/auth/IP/landing-page verdict), the list of users
who clicked/submitted/executed, and any post-compromise activity per user.

### Reasoning
Name the signals and how they stacked — a lookalike-domain campaign
delivered to forty mailboxes, six credential submissions, and one of those
accounts then signing in from a new ASN and adding an inbox rule, is a
confirmed-compromise incident scoped to those users; a single reported
newsletter from an authenticated, reputable sender with no harvesting page
is benign.
