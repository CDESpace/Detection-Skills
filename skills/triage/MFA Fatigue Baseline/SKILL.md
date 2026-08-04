---
name: MFA Fatigue Baseline
description: |-
  Triage MFA-fatigue (push bombing) detections from Entra ID sign-in
  logs, where a burst of MFA denials (sign-in error code 500121 —
  `status.errorCode` natively, `status_code` when normalized to OCSF)
  is followed by a successful login. Separates real coercion from
  habitual deniers by checking VIP membership, denial velocity, and the
  user's historical denial baseline.
type: triage
version: 1.0.0
metadata:
  author: vega-security
  labels:
    - identity
    - entra-id
    - mfa
    - cloud
---

# MFA Fatigue Triage

MFA-fatigue detections fire when a principal accumulates a high count of
MFA denials (Entra ID sign-in error code `500121` — `status.errorCode`
natively, `status_code` if your pipeline normalizes to OCSF) inside a
short window and at least one successful sign-in (error code `0`) lands
in the same window. (Code `500121` covers user-declined, timeout, and
fraud-reported outcomes; Entra's `additionalDetails` field distinguishes
them.) The pattern is high-signal for push bombing, but it also
matches users with broken authenticators, aggressive conditional-access
re-prompting, or a habit of reflexively dismissing prompts. Triage decides
whether the success at the end of the burst was the attacker getting in.

## Inputs

The triggering aggregate for one user and one 15-minute window:
`actor.user.name`, `mfa_denial_count`, `successful_login_count`,
`src_ips`, `apps`, `user_agents`, `first_seen`, `last_seen` — plus access
to the raw sign-in events for the window and the preceding baseline
period.

## Triage steps

Run all three checks. Each check produces exactly one outcome: **RISK**
or **CLEAR**.

### Check 1 — VIP membership

Is `actor.user.name` present in your organization's VIP / high-value-target
list (executives, admins, finance approvers — however your environment
tracks them, e.g. a lookup table or watchlist)?

- Present → **RISK** (`vip-target`)
- Absent → **CLEAR**

### Check 2 — Denial velocity

Pull the individual denial events behind `mfa_denial_count` and compute
the inter-attempt gaps across the window. Did the denials happen in
extremely short succession?

- **RISK** (`burst`): 10+ denials with a median gap ≤ 30 seconds, or any
  run of 5+ denials inside a single minute — scripted or rapid manual
  push bombing.
- **CLEAR**: denials spread across the window with median gaps measured
  in minutes — consistent with re-prompt loops or user fumbling.

### Check 3 — Denial baseline

Confine baseline lookups to a bounded recent window — the alert's
calendar day (UTC) is usually sufficient and keeps queries cheap. Within
that window, examine the user's sign-in logs **excluding the alert's
15-minute window**. Does this user deny many MFA attempts as a matter of
course?

- **CLEAR** (`habitual-denier`): ≥ 5 denials outside the alert window, or
  denials occurring in 3+ separate hours of the day — threshold-crossing
  noise is normal behavior for this user.
- **RISK** (`anomalous-volume`): few or no denials outside the alert
  window — the burst is isolated, new behavior for this user.

## Decision rule

Count the RISK outcomes:

- **2 or 3 of 3 → `escalate`**
- **0 or 1 of 3 → `dismiss`**

No overrides, no exceptions: the rule is a majority of checks. Borderline
measurements (e.g. median gap of 31 seconds) resolve toward RISK for
checks 1–2 and toward CLEAR for check 3; note the borderline call in the
reasoning.

## Output

### Decision

`escalate` or `dismiss`, plus the risk count (e.g. `2/3`) and the outcome
label of each check (`vip-target` / `burst` / `anomalous-volume` or their
CLEAR counterparts).

### Evidence

The window aggregate, the VIP-list check result, the computed inter-attempt
gap distribution (min / median / longest run), and the same-day baseline
denial counts (outside the alert window, bucketed by hour).

### Reasoning

One line per check stating its outcome and the measurement behind it,
then the tally. A dismissal must show the tally, not a gut call — never
dismiss on volume alone.
