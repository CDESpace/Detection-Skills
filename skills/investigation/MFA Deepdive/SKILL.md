---
name: MFA Deepdive
description: |-
  Investigate escalated MFA-fatigue (push bombing) alerts from Entra ID
  sign-in logs. Reconstructs the denial-to-success timeline, attributes
  the source infrastructure, inspects post-authentication activity for
  persistence, and checks for a wider campaign before returning a verdict
  with recommended containment actions.
type: investigation
version: 1.0.0
metadata:
  author: vega-security
  labels:
    - identity
    - entra-id
    - mfa
    - cloud
---

# MFA Fatigue Investigation

Runs on alerts escalated by triage (see `mfa-fatigue-triage`): a user
accumulated a burst of MFA denials and a successful sign-in landed in the
same window. Triage established that the pattern is anomalous for this
user; investigation establishes whether the success was the attacker's.
The question to answer is not "did push bombing happen" — it did — but
"did it work, and what did they do with it."

## Inputs

- The escalated alert (user, window, denial/success counts, source IPs,
  apps, user agents) and the triage report with its check outcomes.
- Raw Entra ID sign-in and audit logs. Confine all comparisons to a
  bounded recent window — the alert's calendar day (UTC) is usually
  sufficient and keeps queries cheap.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Timeline reconstruction

Order every sign-in event for the user across the day. Establish: when
the denial burst started and ended, where the successful login sits
relative to the burst (mid-burst or terminal success is the attacker
pattern; a success hours before an evening burst is not), and whether
denials continued after the success (they usually stop once the attacker
is in).

### 2. Source attribution — signal A

Compare the successful login's source against the user's own activity
from the rest of the day (outside the alert window): source IP, country,
ASN, and user agent.

- **Signal A fires** when the success came from infrastructure the user
  never touched that day — new country, new ASN (especially hosting/VPS
  ranges), or a user agent absent from their other sign-ins.
- Also record whether the denial-storm IPs and the success IP are
  related — same attacker infrastructure on both is a stronger story.

### 3. Post-authentication activity — signal B

Inspect the audit log after the successful login for actions that
convert access into persistence:

- new MFA method / security-info registration
- new device registration or join
- inbox rules, OAuth consent grants, or app password creation
- privileged role activation or directory changes

**Signal B fires** on any of these within the day. A success with zero
post-auth footprint leaves B silent.

### 4. Campaign check — signal C

Search the day's sign-in logs for the denial-storm and success IPs across
**other** users. **Signal C fires** if the same infrastructure targeted
additional accounts — this alert is then one instance of a campaign, and
the report must list the other targets for separate handling.

## Verdict rule

- **`malicious`** — Signal A **and** (B or C), **or** B and C together:
  the attacker authenticated from their own infrastructure and either
  dug in or is running a campaign — or blended into the user's own
  geography (e.g. a residential proxy in the user's country and ASN) but
  both dug in and hit other accounts.
- **`suspicious`** — any other case in which at least one signal fires,
  or the success is terminal to the burst with no contradicting
  evidence: coercion is likely but unproven.
- **`benign`** — no signal fires and the success matches the user's own
  same-day infrastructure: the user eventually approved their own prompt.
- **`inconclusive`** — required data is missing (no audit logs, truncated
  window). Say precisely what was unavailable.

## Output

### Verdict

`malicious` / `suspicious` / `inconclusive` / `benign`, plus which of
signals A, B, C fired.

### Recommended actions

Scale to the verdict — for `malicious`: revoke all refresh tokens and
active sessions, remove attacker-registered MFA methods and devices,
reset credentials, block the source infrastructure, and open incidents
for every account surfaced by the campaign check. For `suspicious`:
session revocation plus user confirmation. Never recommend auto-applying
detection changes — that is the tuning phase's job.

### Evidence

The ordered timeline, the source-comparison table (success vs same-day
baseline: IP / country / ASN / user agent), the post-auth audit entries,
and the campaign IP-overlap results.

### Reasoning

One line per signal stating fired/silent and the observation behind it,
then the verdict derivation from the rule above.
