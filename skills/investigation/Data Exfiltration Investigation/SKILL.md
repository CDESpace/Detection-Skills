---
name: Data Exfiltration Investigation
description: |-
  Investigate an escalated data-exfiltration alert. Quantifies what actually
  left — volume against baseline, the data's sensitivity, and the destination
  — attributes the transfer to a principal and channel, and distinguishes a
  backup or sanctioned sync from theft before returning a verdict with scope
  and containment actions.
type: investigation
version: 1.0.5
metadata:
  author: dwelltime
  labels:
    - data
    - cloud
    - exfiltration
    - insider-threat
---

# Data Exfiltration Investigation

Runs on alerts escalated by triage (see the cloud and application
exfiltration triage skills): a principal moved an unusual volume of data,
or sent it to an unusual destination, in a way triage judged anomalous.
Triage established the transfer looked wrong; investigation quantifies it
and attributes it. The question is not "did data move" — it did — but "how
much, how sensitive, where to, and who sent it."

## Inputs

- The escalated alert (principal, source store, destination, volume, timing)
  and the triage report.
- Access and data-transfer logs (cloud storage access logs, DLP events,
  proxy/egress logs, SaaS download/export logs), the principal's activity
  history, and data-classification metadata where available.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Volume and baseline — signal A

Measure what actually moved and compare it to the principal's own history
and their peers'. **Signal A fires** when the volume is a sharp departure
from baseline — orders of magnitude over what this principal, role, or
service normally transfers — and especially a bulk pull (a whole bucket,
a full mailbox, an entire table) rather than incremental access.

### 2. Sensitivity — signal B

Classify what left, not just how much. **Signal B fires** when the data is
sensitive — credentials/secrets, regulated PII/PHI, source code, customer
databases, or crown-jewel stores — using classification labels, path/bucket
names, and sampled content. A large transfer of public or low-value data
weighs far less than a small transfer of secrets.

### 3. Destination and channel — signal C

Attribute where it went and how. **Signal C fires** when the destination is
external and unsanctioned — a personal cloud account, a newly-seen domain,
an anonymizer, an attacker-controlled host — or the channel is an evasion
(archived/encrypted before send, DNS/ICMP tunneling, a covert upload).
An internal or sanctioned destination (approved backup, corporate SaaS)
weakens it.

### 4. Actor and intent — signal D

Attribute the transfer to a principal and situate it. **Signal D fires**
when the actor is compromised or acting against pattern: the principal was
flagged earlier in an intrusion, a service account moved data it never
touches, or a departing employee bulk-pulled right before leaving. This
separates theft from a legitimate-but-noisy job.

## Verdict rule

- **malicious:** signal C plus A or B — sensitive or high-volume data to an
  unsanctioned destination or through an evasion channel, especially tied to
  a compromised or against-pattern actor (D). Secrets or a customer database
  leaving to attacker-controlled infrastructure is malicious on its own.
- **suspicious:** an anomalous transfer (A or B) whose destination can't be
  cleared as sanctioned and whose actor intent can't be established, but
  benign use can't be shown either.
- **inconclusive:** the transfer volume, contents, or destination can't be
  reconstructed because transfer/DLP logs are missing.
- **benign:** the transfer resolves to a sanctioned job — a scheduled backup,
  an approved data-pipeline sync, a user moving their own files to corporate
  storage — matching the principal's baseline and role, to an internal or
  approved destination, with no sensitivity or evasion concern.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it.

### Recommended actions
When not benign: revoke the principal's access to the source store and
active sessions, block the destination, preserve transfer logs and any
staged archives, notify data-owner and privacy/legal when regulated or
customer data is confirmed out, and hunt for the same principal/destination
across other stores. Scale notification to the sensitivity found in step 2.

### Evidence
The measured volume against baseline, the classification of what left, the
destination attribution and channel, the actor and their status, and the
window and source store involved.

### Reasoning
Name the signals and how they stacked — a service account archiving an
entire customer database and pushing it to a personal cloud account it has
never used, right after that account was flagged, is malicious; the nightly
backup job copying its usual volume to the approved backup bucket is benign.
