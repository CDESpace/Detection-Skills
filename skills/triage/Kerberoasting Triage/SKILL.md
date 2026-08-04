---
name: Kerberoasting Triage
description: Triage an alert where an Active Directory account requested service
  tickets in a pattern that fits Kerberoasting — a burst of TGS-REP requests for
  many service principal names, often with weak RC4 encryption, so the tickets can
  be cracked offline for service-account passwords. Reads the domain-controller
  ticket logs to tell a busy application or a vulnerability scanner apart from an
  actor harvesting crackable service credentials, and decides escalate or dismiss.
type: triage
version: 1.0.3
metadata:
  author: logsmith
  labels:
    - identity
    - active-directory
    - kerberos
    - credential-access
    - lateral-movement
---

# Triage Steps

This class fires on Kerberos service-ticket activity — TGS (ticket-granting
service) requests recorded on a domain controller, event `4769`. Requesting
service tickets is the most ordinary thing on a Windows network: every time a
user opens a file share, a mailbox, or a database, their workstation asks for a
ticket. Kerberoasting hides inside that noise — an actor who already has any
domain foothold asks for tickets to many service principal names at once, then
takes the encrypted tickets offline to crack the service accounts' passwords.
The signal is not that tickets were requested — they always are — but the shape
of the request: how many distinct services, how fast, from one account, and in
what encryption.

Begin with what the requesting account is: a scanner or a service that legitimately
touches many SPNs starts the call near dismiss, while a normal user workstation
suddenly enumerating dozens of service accounts starts near escalate. Then read
the ticket log for the leads below. They stack; a single strong one — a burst of
RC4 tickets for service accounts a user never uses — can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Many SPNs, one requester, one burst.** A single account requesting `4769`
  tickets for a large number of *distinct* service principal names in a short
  window — the enumerate-everything-crackable shape. It weighs most when the SPNs
  span unrelated services (SQL, web, backup, custom apps) the requesting user has
  no reason to touch together.
- **Downgraded to crackable encryption.** Tickets issued with `0x17` (RC4-HMAC)
  when the environment otherwise uses AES — an actor forcing the weaker cipher
  because RC4 service tickets crack far faster offline. `Ticket Encryption Type`
  of RC4 on service accounts that support AES is a strong tell.
- **Targeting the weak, high-value accounts.** Requests concentrated on service
  accounts with old passwords, no rotation, or membership in privileged groups —
  exactly what an attacker enumerates first. Pairs with a foothold signal: the
  requesting account was itself flagged earlier, or the activity comes from a host
  triage already suspects.
- **From a place the account never roasts.** The burst originates from a
  workstation or source the account doesn't normally authenticate from, or at a
  time outside its pattern — a stolen credential driving the enumeration.

**Leads that rule it out** — benign context you can actually see in the data; if
the data doesn't show it, you don't have it:

- **A scanner on record.** The requester is a known vulnerability scanner, an
  identity-hygiene tool, or a red-team engagement documented for this window —
  these enumerate SPNs by design. The account and schedule match the sanctioned
  tool.
- **A busy service being itself.** A single application or service account that
  legitimately talks to many back-ends, requesting the same familiar set of SPNs
  it always does, in its normal encryption — high count, but the same count it
  shows every day and the same services.
- **Encryption matches the environment.** Tickets issued in AES with no RC4
  downgrade, from an account and host that fit baseline — no cipher manipulation
  to explain.
- **Volume that fits the account.** The number of distinct SPNs is in line with
  what this account requests on an ordinary day; a file server or a monitoring
  host touching many services is not new for it.

To confirm a lead instead of guessing, pull the thread: after the ticket burst,
did the requesting account or host show offline-crack follow-through — a later
sign-in as one of the roasted service accounts, or lateral movement using it? A
roast followed by use of a cracked service account is a confirmed credential-access
step, not a suspicion.

# Output

## Decision
- **escalate:** a burst of TGS requests for many distinct SPNs from one account,
  especially forced to RC4 when AES is available, concentrated on privileged or
  stale service accounts, or coming from a host or account already suspect. A roast
  shape followed by a sign-in as one of the targeted service accounts escalates on
  its own.
- **dismiss:** ticket activity traced to a documented scanner or red-team window,
  a known service requesting its usual set of SPNs in its normal encryption, or a
  volume and cipher that positively match the account's baseline. A dismiss is a
  positive call made with the requester's identity and the ticket shape in hand —
  not the mere absence of RC4. When the requester, the SPN spread, or the encryption
  can't be placed against baseline, escalate.

## Evidence
The `4769` events (requesting account, source host, distinct SPNs, ticket
encryption types, timing), what the requesting account and host are and their
baseline SPN pattern, whether any scanner or red-team activity is on record for the
window, and any follow-on authentication as the targeted service accounts.

## Reasoning
Name the leads that decided it and how they stacked — one user account pulling RC4
tickets for thirty unrelated service SPNs in a minute, then signing in as one of
them, is escalate on its own; a documented BloodHound scan or a file server
requesting its usual AES tickets is dismiss.
