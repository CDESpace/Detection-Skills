---
name: Service Account Noise
description: Tune a detection that a non-human identity keeps firing — an
  infrastructure-as-code role creating IAM resources, a cloud service launching
  instances on schedule, an integration or backup account reading at machine
  scale. Judges whether the actor is genuinely a service doing the job it was
  built for, proves the pattern is durable and explains a recurring share of the
  noise, and builds an exclusion pinned to the identity and its durable source
  so a human or an attacker performing the same action still alerts.
type: tuning
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - exclusion
    - service-account
    - automation
    - false-positive
    - noise-reduction
---

# Tuning Methodology

This use case fires on detections built to catch a human doing something — creating IAM roles, launching instances, reading records in bulk — that an automation does all day as its job: a Terraform or Scalr provisioning role creating the roles it manages, `autoscaling.amazonaws.com` launching instances on demand, an access-review service running the same lookups whenever a review opens, a backup agent reading at volumes no person would. The activity is benign for a structural reason that holds every time: a service did it, not a person, so there are no human credentials behind it to steal or misuse, and it performs exactly the operation it was built for.

A tuning is a permanent change to a live detection, so the question is never "was this run benign?" It is whether this identity is a durable, explainable source of benign noise. Confirm the actor is genuinely non-human — a service principal, an instance or pipeline role, an account that never logs in interactively — not a person's account that automation happens to borrow. Then establish durability the way you would a baseline: query for it. How much of this detection's recent firing does the identity explain, and does it recur across the window, or did it appear once? A service that accounts for most of the noise and keeps firing for the same reason is a real tuning; a single benign sighting is not.

Read the detection's intent before excluding. If the detection exists to watch automation itself — anomalous service-account usage, credential abuse of machine identities — then the service account is the very signal the detection was built to surface, and excluding it deletes the detection's reason to exist. Decline, however benign this case looked. Scope is a hard rule: tune only on identities that appeared in the triggering incident, never invent values, and check the detection's current logic first — a value already excluded by a prior clause is already tuned.

The clause is appended to the detection as a filter and is never negated for you: it must exclude the benign by NOT matching it. A bare match (`==`, `contains`, `in`) keeps only the benign and silently disables the detection — the one unforgivable mistake. A single identity takes a `!`-prefixed operator (`actor.user.name != "scalr-terraformer"`); a compound takes the benign match wrapped as a unit (`not(actor.user.name == "scalr-terraformer" and src_endpoint.ip == "10.20.0.5")`) — never hand-expanded into separate `!=` terms, which over-excludes. Read field paths off the actual triggering events, not from memory. Then adversary-test it: an attacker can assume a role or steal a service credential, so if this identity turned hostile, would the filter blind the detection? Pin the exclusion to the identity together with the durable source it always operates from — the invoking service, the pipeline host, the role path — so the same name appearing anywhere else still alerts.

# Output

## Action
**exclude** — one filter clause appended to the detection removing the service identity's routine operation; when the actor turns out to be a person, the pattern appeared once, or the detection watches machine identities by design, propose nothing — a precise decline beats an exclusion that widens a blind spot.

## Target
The detection whose false positive was confirmed — one appended filter clause on a field present in its current logic.

## Value
The clause, one line: the service identity pinned to its durable source — `not(actor == <identity> and <source field> == <its origin>)`, or a single `!=` when the identity alone is unambiguous. Never a bare match operator.

## Evidence
The triggering events the identity and field paths were read from; the identity's type and authentication pattern proving it is not a person; aggregation counts showing the share of the detection's recent firing it explains and its recurrence; the detection's current logic and existing tuning suggestions.

## Reasoning
The mechanism, not the measurements: this is a service doing the job it was built for, with no human credentials behind it to abuse — and what still alerts: the same action by any person, or this identity operating from anywhere but its own source.
