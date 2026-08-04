---
name: impossible-travel-tuning
description: |-
  Tune impossible-travel detections from closed-case outcomes. Reads the
  triage report, the investigation report, and the analyst's verdict, then
  proposes exactly one detection change — an egress exclusion, a threshold
  modification, or a fork for a high-risk population — for human review.
type: tuning
version: 1.0.0
metadata:
  author: vega-security
  labels:
    - identity
    - okta
    - entra-id
    - cloud
---

# Impossible Travel Tuning

Runs after a case is closed. The goal is not to judge the alert again — it
is to decide whether the detection itself should change so the next
occurrence of this pattern is either suppressed earlier or caught with more
context. Every proposal is a suggestion for human review; nothing is
auto-applied.

## Inputs

- **Triage report** — the gate that resolved, the dismissal reason code or
  escalation evidence, and the egress/device/MFA facts gathered.
- **Investigation report** — the verdict, the evidence chain, and any
  infrastructure indicators (ASNs, IP ranges, device fingerprints).
- **Analyst verdict** — the human's final disposition and any notes on why
  it differed (or not) from the automated verdict.

## Tuning procedure

Work through these in order and stop at the first that applies.

### 1. Recurring benign egress

If the case was dismissed (or investigated to `benign`) because of egress
infrastructure that is **not yet in the known-egress inventory** — a new
corporate VPN range, a SASE point of presence, a carrier NAT block seen
repeatedly for this population — propose `exclude` with the specific range
or ASN as the value. Cite every prior case that hit the same range.

### 2. Over-broad exclusion

If a true positive was suppressed or delayed by an existing exclusion — or
the investigation shows an inventoried egress range now also covering
attacker infrastructure — propose `include`: remove or narrow that
exclusion, citing the case it hid and any others that would resurface.

### 3. Threshold friction

If the last 30 days show three or more benign cases whose computed travel
velocity sits just above the current threshold (within 20%), propose
`modify` on the velocity threshold or the minimum-distance floor. Include
the velocity distribution of recent true and false positives so the
reviewer can see what the new threshold would have suppressed.

### 4. Population mismatch

If the case shows the detection performing well generally but poorly for an
identifiable population — executives who travel weekly, a region with known
GeoIP drift, service accounts that should never travel at all — propose
`fork`: a copy of the detection scoped to that population with tightened or
loosened gates, leaving the base detection untouched.

### 5. No change

If the alert worked as designed — escalated a true positive or dismissed an
explained anomaly with an inventoried reason — return the action `none`
with no target or value. A tuning skill that always suggests something
trains reviewers to ignore it.

## Output

### Action

One of `exclude` | `include` | `modify` | `fork` | `none`. `none` is the
explicit no-change result — return it with reasoning rather than omitting
a proposal.

### Target

The detection ID or inventory list the change applies to (empty for
`none`).

### Value

The specific range, ASN, threshold, or fork scope to apply (empty for
`none`).

### Evidence

Prior-case references, hit counts, and the expected alert-volume impact.
One proposal per run — if several gates apply, return the one with the
largest false-positive reduction and note the runners-up here.

### Reasoning

Which gate applied, the case facts that satisfied it, and why the proposed
change (or `none`) follows from them.
