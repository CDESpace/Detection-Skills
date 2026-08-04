---
name: Suspicious MFA Enrollment Triage
description: Triage an alert where a new MFA method was registered on an account —
  an authenticator app, phone, or security key added or changed. Reads the audit
  trail and the session that registered it to tell a user setting up a new phone or
  completing onboarding apart from an attacker planting their own factor to hold an
  account after a takeover, and decides escalate or dismiss.
type: triage
version: 1.0.2
metadata:
  author: logsmith
  labels:
    - identity
    - mfa
    - account-takeover
    - persistence
---

# Triage Steps

This class fires when an authentication method is registered or changed on an
account — a new Authenticator app, a new phone number, an added FIDO key, in Entra
ID, Okta, or another identity provider. Enrolling a factor is a routine thing:
people get new phones, complete onboarding, add a backup key, re-enroll after a
lockout. It is also the single cleanest way an attacker keeps an account after
stealing it — register their own factor, and they satisfy MFA from then on even
after the user resets the password. The signal is not that a method was added — it
is who added it, from where, and what state the account was in when they did.

Begin with the account's recent history: a method registered in the same window as
a sign-in triage already flagged, or right after a password reset from an unfamiliar
source, starts the call near escalate. A registration during a documented onboarding,
or from the user's own known device, starts near dismiss. Then read the audit event
and the registering session for the leads below. They stack; a single strong one — a
factor added from a new country right after a suspicious login — can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Registered in a takeover window.** The method was added in the same session or
  hour as a sign-in from a new device/ASN, an MFA-fatigue success, or a token replay
  — the enroll-my-own-factor persistence step immediately after access. The
  registration and the suspicious sign-in sharing a source IP or client is the strong
  version.
- **From a place and device the user doesn't use.** The registration event's source
  IP, country, ASN, or client is one the account has no history with — the real user
  almost always enrolls from a device and network they already sign in from.
- **Right after a reset from an unfamiliar source.** A password reset or SSPR
  followed immediately by a new method, where the reset itself came from a source that
  doesn't match the user — the full account-recovery-hijack shape.
- **Replacing, not adding.** An existing trusted method removed and a new one added in
  the same window, or a new method made primary and the user's own demoted — an
  attacker locking the real user out, not a user adding a backup.

**Leads that rule it out** — benign context you can actually see in the data; if the
data doesn't show it, you don't have it:

- **Onboarding or a known refresh.** The registration falls in the user's first-week
  onboarding, or matches a documented device refresh or a helpdesk-assisted re-enroll
  on record for this person.
- **From the user's own session.** The method was added from a device, network, and
  session that positively match the account's baseline, with no takeover signal near
  it — a second factor added from the same laptop they always use.
- **Additive and expected.** A new backup key or app added alongside the existing
  methods, none removed, on an account with no suspicious sign-in anywhere near the
  event.
- **A user-confirmed change.** The person confirms they enrolled the new factor, or a
  scheduled bulk enrollment the org ran is on record.

To confirm a lead instead of guessing, pull the thread: after the enrollment, was the
new factor immediately used to satisfy MFA on a fresh sign-in from the same suspicious
source, and did the account's own methods get removed? A new factor plus its immediate
use from attacker infrastructure is a confirmed persistence step, not a suspicion.

# Output

## Decision
- **escalate:** a method registered in the same window as a flagged sign-in, from a
  source or device the account never uses, right after a reset from an unfamiliar
  source, or one that replaces the user's own factors. Any enrollment paired with a
  takeover signal on the same account escalates on its own.
- **dismiss:** a registration during documented onboarding or a known device refresh,
  from a session that matches the account's baseline with no takeover signal near it,
  or an additive method with the user's own factors left intact and no suspicious
  activity around it. A dismiss is a positive call made with the registering session
  and the account's context in hand — not the mere fact that enrollments are common.
  When the source, the device, or the account's state can't be placed against baseline,
  escalate.

## Evidence
The registration event (method type, action, source IP, country, ASN, client, timing),
the account's sign-in baseline and takeover status around the change, whether a reset
preceded it, whether existing methods were removed or demoted, and any sign-in that
immediately used the new factor.

## Reasoning
Name the leads that decided it and how they stacked — a new Authenticator added from a
hosting-provider IP minutes after an MFA-fatigue success, with the user's own method
removed, is escalate on its own; a backup key added from the user's usual laptop during
their onboarding week is dismiss.
