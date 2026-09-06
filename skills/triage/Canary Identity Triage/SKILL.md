---
name: Canary Identity Triage
description: |-
  Triage authentication events against a decoy identity — an account that
  exists only to be touched. Any successful logon, failed logon, or
  lockout against a canary is critical by definition: there is no
  legitimate reason for anyone to authenticate as an account nobody owns.
  Verify the canary is present and disabled (a live canary is a foothold,
  not a tripwire), classify the touch by event ID and source, and return
  the attacker's source IPs as the containment shortlist. Covers planted
  decoys and name-convention strays (honey, canary, decoy) that were
  created without being registered.
type: triage
version: 1.0.0
metadata:
  author: DrOlu
  labels:
    - canary
    - honeypot
    - identity
    - patient-zero
    - windows
---

# Canary Identity Triage

A canary (decoy/honey) identity is an account created to appear valuable —
`honeyadmin`, a stale-looking `svcbackup2` — and given to no one. It exists
only to be touched. That property makes it the highest-signal detector in
identity security: a phishing campaign that enumerates users will find it,
a password spray will try it, an attacker reading group membership will
want it. **Any authentication attempt against it is attack evidence, not a
signal to be scored** — there is no false-positive class to rule out, no
service account that legitimately logs in as honeyadmin at 3am.

Run this triage when identity telemetry shows authentication activity for
an identity in the canary set, or when auditing an estate to confirm its
canaries are armed and watching.

## Inputs

- The canary inventory: which decoy identities are declared, and on which
  hosts they are planted.
- Windows Security event log access (4624 successful logon, 4625 failed
  logon, 4740 account lockout) for the hosts the canaries live on.

## Triage steps

### 1. Verify the canary is present, disabled, and deliberate

Before treating a touch as attack evidence, confirm the account is actually
a canary: it must exist, be **disabled** (a canary that can log on is a
foothold you planted, not a tripwire), never expire, and be describable —
a `Description` marking it as a decoy prevents a well-meaning admin from
"cleaning it up." If the account is enabled, treat the account itself as an
open door and disable it before anything else. Cover two populations:
registered canaries from the inventory, and name-convention strays —
accounts matching honey/canary/decoy/tripwire patterns that were planted
but never registered. An unregistered canary still detects, but nothing
watches for its hits.

### 2. Classify the touch by event ID

Any of the three is attack evidence, at ascending severity of intent:

- **4625 failed logon against the canary** — someone tried the identity.
  Password spray or targeted guessing reached it. Record source IP, logon
  type, and auth package.
- **4740 lockout of the canary** — sustained guessing hit the account
  lockout threshold. The attempt was heavy enough to trip policy; the
  source has committed volume.
- **4624 successful logon against the canary** — worst case. The canary
  was disabled, so a success means the attacker enabled it, created a
  parallel account, or the canary was misconfigured. Treat as active
  compromise: capture the session (logon ID, source, process context)
  before the containment step kills it.

Group the events by source IP and identity — one source touching three
canaries is a campaign; three sources touching one canary is a spray.

### 3. Extract the containment shortlist from the touches

The value of the canary is that it names the attacker: collect the distinct
source IPs from all touches, newest first, and treat them as the block
shortlist. Contrast with a brute-force against a real account, where the
source needs corroboration — here the identity itself vouches for the
malice. The shortlist goes straight to firewall blocking; the canary needs
no corroboration because it has no legitimate use.

### 4. Confirm the estate's canary coverage

A triage that finds nothing may mean the attacker has not arrived — or that
the estate has no canaries to touch. Check the coverage state: how many
canaries are planted per host, are they all disabled, are they registered
so hits are watched. An estate with zero canaries has no patient-zero
tripwire; recommend planting two or three per host (disabled, decoy-named,
never-expiring) before closing the triage.

# Output

## Action
**escalate** — any touch is critical: hand the distinct source IPs to
containment (firewall block) and open an investigation into how the source
learned the canary identity (enumeration vector, credential leak, list
re-use from another estate).

## Target
The touched canary identity and the source IPs that touched it — plus, when
the canary was found enabled or missing, the canary account itself as an
immediate fix.

## Evidence
The 4624/4625/4740 events with source IP, logon type, auth package, and
timestamp; the canary's account state at triage time (disabled, never
expires, decoy description); the coverage count of armed canaries across
the estate.

## Reasoning
The mechanism, not the measurements: a decoy identity has no owner, no
purpose, and no legitimate traffic, so any authentication against it is an
attacker revealing themselves on an identity nobody would defend. That
removes the false-positive analysis entirely — the only questions are where
they came from, what they tried, and whether they got in.
