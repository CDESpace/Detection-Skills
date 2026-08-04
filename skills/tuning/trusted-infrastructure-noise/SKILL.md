---
name: Trusted Infrastructure Noise
description: Tune a detection that the org's own infrastructure keeps firing by
  design — the vulnerability scanner tripping recon and port-scan detections,
  corporate VPN or NAT egress tripping impossible-travel and risky-geo sign-in
  rules, an internal web app or a reputation-miscategorized domain tripping
  egress detections, a phishing-simulation platform tripping email rules.
  Validates the infrastructure against what the org actually documents, excludes
  the documented range or host scoped to the behavior the tool generates, and
  keeps the detection alive for the same behavior from anywhere else.
type: tuning
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - exclusion
    - trusted-infrastructure
    - scanner
    - egress
    - false-positive
    - noise-reduction
---

# Tuning Methodology

This use case fires on detections doing exactly their job against traffic the org generates on purpose: the vulnerability scanner sweeping subnets and probing ports the way recon detections are built to catch, every remote employee surfacing at the same corporate VPN or NAT egress IPs until impossible-travel and risky-geo rules drown in them, an internal company web app or a domain the reputation feed miscategorized turning routine uploads into egress alerts, a phishing-simulation platform tripping the email rules it deliberately imitates. The activity is benign for a structural reason that holds every time: this is the org's own tooling producing the same traffic by design.

Trusted is a claim you verify, not a feeling of familiarity. The exclusion stands on documentation — the scanner's published source ranges, the egress and VPN IP inventory, the application's ownership, the simulation platform's sending infrastructure — never on "we see it a lot," because an attacker's persistent infrastructure also shows up a lot. Then establish durability by querying: how much of the detection's recent firing do these sources explain, and do they recur across the window for the same reason? A documented source that carries most of the noise is a real tuning; an undocumented address that merely recurs is a finding, not an exclusion.

Scope the clause to what the tool actually does, not to everywhere it lives. Exclude the documented hosts or ranges — never a broad CIDR, never "anything internal" — and where the detection allows it, pin the exclusion to the behavior the tool generates: the scanner's sweep against the recon rule, the egress IP against the geo logic. A shared egress IP explains the network hop and nothing else — a new device or a new region seen behind it still has to alert. Check the detection's current logic first (a range already excluded is already tuned), tune only on sources that appeared in the triggering incident, and read field paths off the actual triggering events.

The clause is appended to the detection as a filter and is never negated for you: it must exclude the benign by NOT matching it — a bare match (`==`, `in`, `contains`) keeps only the benign and silently disables the detection. A single source takes a `!`-prefixed operator (`src_endpoint.ip != "203.0.113.7"`); a documented set takes `not(src_endpoint.ip in ("203.0.113.7", "203.0.113.8"))`; a host-plus-behavior pin takes `not(src_endpoint.ip == <scanner> and dst_port in <its sweep>)`. Then adversary-test it: this infrastructure is shared — an attacker on the VPN egresses from the same IP, a compromised scanner host probes from the same address. If the filter would blind the detection to that, narrow it to the tool's own behavior or decline; the exclusion must leave the same behavior from any other source, and different behavior from these same hosts, still alerting.

# Output

## Action
**exclude** — one filter clause appended to the detection removing the documented infrastructure's designed behavior; when the source is undocumented, the pattern appeared once, or any workable clause would also cover attacker traffic riding the same infrastructure, propose nothing.

## Target
The detection whose false positive was confirmed — one appended filter clause on a field present in its current logic.

## Value
The clause, one line: the documented host, range, or domain, scoped to the behavior the tool generates — a `!`-prefixed operator for a single source, `not(... in (...))` for a documented set, `not(<source> == X and <behavior field> == Y)` for a behavior pin. Never a broad CIDR, never a bare match operator.

## Evidence
The org's documentation tying the source to its function — scanner ranges, egress inventory, app ownership, simulation-platform infrastructure; the triggering events the field paths were read from; aggregation counts showing the share of recent firing these sources explain and their recurrence; the detection's current logic and existing tuning suggestions.

## Reasoning
The mechanism, not the measurements: this is the org's own documented tooling producing this traffic by design — and what still alerts: the same behavior from any undocumented source, and anything these hosts do beyond the behavior that was excluded.
