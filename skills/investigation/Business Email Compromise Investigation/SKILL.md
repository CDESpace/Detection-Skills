---
name: Business Email Compromise Investigation
description: |-
  Investigate an escalated business email compromise alert. Confirms mailbox
  access, reconstructs thread hijacking and any payment-redirect or invoice-
  fraud attempt, audits the persistence the actor left, and scopes internal
  and external recipients before returning a verdict with containment and
  finance-notification actions.
type: investigation
version: 1.1.2
metadata:
  author: logsmith
  labels:
    - email
    - bec
    - identity
    - account-takeover
    - fraud
---

# Business Email Compromise Investigation

Runs on escalations where a mailbox may be in an attacker's hands — from
inbox-rule-abuse triage, an account-takeover flow, or a reported fraudulent
message. Triage established the account or a message looked wrong;
investigation establishes whether the mailbox was truly controlled, what the
actor did with it, and whether money or trust was redirected. The question is
not "was the account suspicious" — it was — but "did an actor operate the
mailbox, and what did they send, redirect, or read."

## Inputs

- The escalated alert (mailbox, suspicious sign-in or rule or reported
  message, timing) and the triage report.
- Mailbox audit logs (sign-in, message send/read, rule and delegate changes),
  message-trace across the tenant, the sign-in logs for the owner, and the
  sent-items and rule state for the mailbox.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Access confirmation — signal A

Confirm the mailbox was accessed by someone other than the owner. **Signal A
fires** on a sign-in or mailbox access from infrastructure the owner never
uses (new ASN/country/client), a token replay, or non-owner access that
triage flagged — establishing control, not just a suspicious message. Fix
the window of attacker control from first to last anomalous access.

### 2. Thread hijack and outbound fraud — signal B

Read what was sent from the mailbox during the control window. **Signal B
fires** when the actor replied within existing threads (thread hijacking to
borrow trust), sent invoice/payment/wire-change requests, or messaged
finance, vendors, or customers with redirect instructions. Capture recipients
(internal and external) and any changed bank/payment details — this is the
fraud core of BEC.

### 3. Persistence and concealment — signal C

Audit what the actor left to keep access and stay hidden. **Signal C fires**
on inbox rules that forward or delete replies (see `inbox-rule-abuse-triage`),
added delegates or forwarding, a new MFA method (see
`suspicious-mfa-enrollment-triage`), or OAuth grants — the machinery that
keeps the fraud running and buries the evidence from the real owner.

### 4. Recipient and reach scoping — signal D

Scope who was touched: everyone the fraudulent mail reached, whether any
recipient acted (replied, paid, changed details), and whether the actor
pivoted to other internal mailboxes with the harvested trust. **Signal D
fires** when the reach extends beyond the one mailbox — recipients who acted,
or lateral spread to colleagues — setting the true incident scope.

## Verdict rule

- **malicious:** signal A plus B or C — confirmed non-owner control with
  outbound fraud or attacker persistence. Any confirmed payment redirect or
  a recipient who acted on it (in D) is a high-severity malicious incident on
  its own.
- **suspicious:** access anomalies (A) or fraud-shaped mail (B) where control
  can't be fully confirmed and no benign explanation fits either.
- **inconclusive:** mailbox audit or message-trace logs are missing, so
  access, outbound mail, or reach can't be reconstructed.
- **benign:** the activity resolves to the legitimate owner — a sign-in and
  the messages both match their baseline and role, a rule or delegate they
  set themselves, no fraud-shaped outbound mail, no attacker persistence. A
  misjudged-but-legitimate account.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it, and an explicit recipient/impact scope.

### Recommended actions
When not benign: reset the owner's password and revoke all sessions/tokens,
remove attacker rules/delegates/forwarding and rogue MFA methods, purge
fraudulent messages tenant-wide, and — critically for BEC — notify finance
and every recipient of a payment-redirect request to halt or claw back
transfers, and alert affected vendors/customers. Escalate to fraud/legal when
money moved. Scope to the reach found in step 4.

### Evidence
The attacker-control window and access attribution, the fraudulent messages
sent with recipients and any changed payment details, the persistence
mechanisms left behind, and the full internal/external reach with any
recipients who acted.

### Reasoning
Name the signals and how they stacked — a mailbox accessed from a foreign
VPS, replying inside a live invoice thread with new bank details to a customer
who then paid, plus a rule deleting the customer's replies, is a
high-severity malicious BEC scoped to that customer and thread; an owner
sending normal mail from their usual device with a self-made vacation rule is
benign.
