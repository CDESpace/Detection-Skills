---
name: Identity Authentication Abuse
description: Triage a sign-in alert where a credential or session may have
  landed in the wrong hands — brute force, password spray, MFA fatigue or
  bypass, adversary-in-the-middle and token replay, impossible travel, risky or
  scripted logins, session-cookie reuse, and anonymized sign-ins. Reads the
  sign-in logs and session fingerprint to tell failed-and-stopped noise and
  sign-ins the actor's own pattern explains apart from a login that actually got
  in, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - authentication
    - mfa
    - account-takeover
---

# Triage Steps

This class fires on the act of authenticating — failed and odd sign-ins, MFA prompts, and session activity for a user or service account. Most of it is noise: people fat-finger passwords, an app keeps retrying an expired credential, someone signs in from a hotel on a trip. Sign-in events also look alike whether the attempt got in or bounced off, so the fact that an alert fired is not the signal. The signal is whether access was actually granted and whether the actor's own pattern explains it. Triage here is reading the sign-in trail and deciding: did this attempt land in the wrong hands, or is it noise that never succeeded?

Begin with this detection's track record on this actor — a rule that fires daily on the same person and is always closed benign starts the call near dismiss — then read the sign-in trail for the leads below. None is required on its own; they stack, and a single strong one (a success at the end of a failure burst, an MFA approval the user never asked for) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Success at the end of a burst.** A run of failed sign-ins followed by one that succeeds — a spray or brute-force run that ends with a token issued. In the logs: many `failure` results, then a `success` against the same account. It carries most weight when the failures span several accounts or the success lands from a source or device the actor does not use; a single account's failures from the actor's own device that end in a success right after a forced password change is a lockout recovery, not a break-in.
- **MFA prompt the user never started.** A string of denied or timed-out MFA challenges, then an approval — the fatigue pattern where the real user finally taps "approve" to stop the buzzing. Repeated `MFA denied` then `MFA satisfied` with no matching sign-in the user initiated.
- **A session reused from somewhere new.** An adversary-in-the-middle or token-replay shape — a session cookie or token first seen on the real user's device now presented by a new client ID from a new network, with no fresh password or MFA. The same session reappearing under a different device fingerprint and ASN is the tell.
- **A device and a place the actor never uses.** A successful sign-in from a device and a geolocation both new to this actor at once — especially one that cleared only weak or non-FIDO MFA — is a takeover shape on its own, with no failure burst or impossible travel needed to reach it. Sign-in from a TOR exit, a hosting provider, or an anonymizer the actor's history has never touched, or impossible travel that no trip or VPN explains, adds to it. A **malicious or suspicious reputation verdict on the sign-in source IP** makes an unfamiliar source decisive.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **No success after the failures.** Failures-only with nothing granted — a typo storm, an expired password, a stale app password retrying. Logs show `failure` repeating and never a `success`.
- **It matches the actor's baseline.** The geo, network, device, and timing positively fit how this account normally signs in — the identity directory (Graph/Okta users, risky-users) carries the actor's history and risk standing, and managed-devices tells you whether the device is one of theirs; a "risky login" from a source already in the actor's usual ASN and region is not new. A new device or a new region is not a baseline match; a documented hardware refresh or the actor's own confirmation is what turns one benign.
- **The trip or egress explains it.** Impossible travel that resolves to a known VPN or corporate egress IP whose reputation is known or clean, or a travel pattern already on record for this person. A shared corporate proxy or egress IP accounts only for the network hop — not a new device or a new region seen behind it.
- **The actor confirms it.** A user-reported sign-in the person later confirms as their own, or a known automation account signing in on its usual schedule.

To confirm a lead instead of guessing, pull the thread: after the suspect sign-in, did the same token reach a mail rule, a file download, or a new MFA registration in the same window? Corroboration turns a suspicious login into a confirmed takeover.

# Output

## Decision
- **escalate:** a success at the end of a spray or from a source or device the actor never uses, an MFA approval the user never started, a session replayed from a new client and network, a sign-in from an anonymizer the actor never uses, or a success from a new device and a new region at once — especially two together, any one with activity after the login, or one that cleared only weak MFA.
- **dismiss:** failures with no success, or a sign-in whose device, source, and geo positively match the actor's established pattern — a lockout recovery after a forced password change fits here — accounts for it, and nothing was granted or followed. A shared corporate egress IP, or the mere absence of a failure burst or impossible travel, is not on its own a reason to dismiss. A dismiss is a positive call that the sign-in is benign, made with that context in hand — a failure run you saw end with nothing granted, a device and geo you matched to the actor's own history; a baseline you couldn't establish or a source you couldn't place in that history is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or a new device and region, a success, or session reuse looks real and nothing positively explains it — escalate.

## Evidence
Whether a success followed the failures, the actor's sign-in baseline (geo, network, device, timing) and risk standing from the identity directory, where the MFA prompt came from, the source's anonymizer or hosting status and its reputation, any session/token reuse across client fingerprints, and prior dispositions for this rule.

## Reasoning
Name the leads that decided it and how they stacked — a spray that ends in a success from a TOR exit, then a new mail rule, or a success from a new device and a new region at once, is escalate on its own; a typo storm that ends in a success from the actor's own device right after a password reset, or a risky login from the actor's normal VPN egress, is dismiss.
