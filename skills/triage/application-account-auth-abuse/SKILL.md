---
name: Application Account Auth Abuse
description: Triage a SaaS account alert about credential and sign-in abuse —
  password spray, brute force, failed-then-successful logins, lockout from many
  IPs, impossible travel, infrequent-country or multi-OS sessions, and activity
  on a terminated or disabled account. Reads whether a success followed the
  attack, the account's status, and geo and posture against the actor's baseline
  to tell broken clients and travel apart from a real takeover, and decides
  escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - credential-access
    - sign-in-anomaly
    - account-takeover
---

# Triage Steps

This class fires on patterns that are noisy by themselves — broken clients, expired passwords, VPNs, and travel produce failures, lockouts, and geo jumps constantly. The fact that an account saw failed logins or a new country is not the signal. The signal is whether the attempt worked and who the account belongs to: an attacker spraying or replaying credentials produces the same failure bursts and odd-geo sessions a misconfigured client does, right up until one attempt succeeds. Triage here is reading whether a success followed the noise, the account's status, and the geo against baseline, and deciding whether it is a broken credential or a real takeover.

Begin with this detection's track record on this actor — a rule that fires daily on a service account hammering one IP with a stale secret and is always closed benign starts the call near dismiss, but a success ending that failure run or a credential change on the account breaks the pattern and stays escalate-reachable — then read the leads below. None is required on its own; they stack, and a single strong one (a success after a spray, any activity on a terminated account) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A success following the attack.** A spray or brute-force burst that ends in a successful authentication for the same actor: many `login failed` then one `login success` from the same source or a new one. A malicious or suspicious reputation verdict on that source IP makes the success decisive. A success after a run of failures — or a success paired with a credential or secret change on the account — escalates even when the failure count is modest; a small burst, or none at all, is not proof of benign. The attempt worked — this is the strongest escalator here.
- **Any activity on a terminated or disabled account.** A login, token use, or action on an account that should be dead: a `success` on a user the identity directory (Graph/Okta users) marks terminated or disabled, or a dead account generating session events. There should be none at all.
- **A first-time-country sign-in that succeeded.** A genuine new-country or new-region session that authenticated against a sensitive actor — not just a geo jump, but a successful one on an account worth taking, and more so on an actor the identity directory already flags (risky-users). Escalate the geo signal only when a first-time country pairs with an actual success.
- **A success from an unusual posture against baseline.** A successful session from an OS, device, or client this actor has never used, alongside the odd geo — the shape of a replayed token or a session on attacker infrastructure, not the actor's known device.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **Failures with no success after them.** Repeated failures that never end in an authentication — the shape of a misconfigured client, an expired-password retry loop, or a stale integration with an old secret.
- **A known automation identity from its fixed egress.** A service account failing from its usual fixed IP or documented egress range with no success after the failures — a broken credential, not an attacker. A success that ends a long failure run, or a credential or secret change on the account, is not covered here: it breaks the broken-credential pattern and stays escalate-reachable.
- **A geo jump a known VPN explains.** Impossible travel or an infrequent country that maps to a known corporate VPN exit or a roaming user's expected path, and the source IP's reputation is known or clean.
- **It matches the actor's baseline.** The same country, device, and client this actor signs in from as normal, with nothing new this time.
- **The account is active and the actor is its owner.** A confirmed active account whose owner's recent baseline includes this source and posture.

To confirm a lead instead of guessing, pull the thread: after the successful login, did the same session change a password, set a forwarding rule, register a new MFA method, or download in bulk in the same window? Corroboration turns a suspicious success into a confirmed takeover.

# Output

## Decision
- **escalate:** a success after repeated failures for the same actor, any activity on a terminated or disabled account, a first-time-country sign-in that succeeded, or a success from a posture this actor has never used — when a success follows the attack pattern, lean escalate even if other signals are clean.
- **dismiss:** failures-only with no following success, or a known automation identity failing from its fixed egress, or a geo jump a known VPN explains, with the account active and matching baseline. A dismiss is a positive call that the sign-in activity is benign, made with that context in hand — a fixed egress you recognized, a VPN you actually matched to the geo jump; a source you couldn't place or an account status you couldn't confirm is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or a success follows the attack pattern, or the account's credential or secret changed — escalate.

## Evidence
Whether a success followed the failures for the same actor, the account status (active / terminated / automation), the source IP, its reputation, and whether it is a known VPN or fixed egress, the country and OS against the actor's history, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — a spray that ends in a successful login followed by a forwarding-rule change is escalate on its own; a service account failing all day from its usual fixed IP with no success is dismiss.
