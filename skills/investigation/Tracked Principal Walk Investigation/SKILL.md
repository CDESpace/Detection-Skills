---
name: Tracked Principal Walk Investigation
description: |-
  Investigate what a privileged identity did across an estate by walking
  its logon chain: collect 4624 logons and 4648 explicit-credential uses
  for the tracked principal on each host, follow the 4648 hops to the next
  machine, and reconstruct the path the identity took. Built around three
  honest-failure rules: a per-host walk budget that stops the walk becoming
  a worm, a verification that each host's audit policy can actually see
  logons before trusting its answers, and termination labels that
  distinguish a true origin from a log-rotation boundary or a blind
  witness. Returns the walk path with a confidence grade, not a guess.
type: investigation
version: 1.0.0
metadata:
  author: DrOlu
  labels:
    - lateral-movement
    - identity
    - windows
    - logon-chain
    - investigation
---

# Tracked Principal Walk Investigation

Run this when a privileged identity (Administrator, a service principal, a
domain admin) is known or suspected to have moved beyond the host where it
was first seen. The question is not "is this identity privileged" — it is
"*where did this identity go, in what order, and how far can we honestly
trace it*".

The method treats the estate as a graph: each host answers "which logons
into me came from where, and which explicit-credential uses point out of
me," and 4648 events (explicit credential use — runas, remote invocation
with alternate credentials) are the edges that let the walk continue to the
next host. The walk is depth-capped because an unbounded hunter is a worm:
each hop costs the same collection effort and the graph can loop.

## Inputs

- The principal to track and the host where it was last seen.
- Access to Windows Security event logs (4624 logons, 4648 explicit
  credential use, 4672 special-privilege assignment) on every candidate
  host.
- A walk budget: how many hops are affordable before the investigation
  stops collecting and starts reasoning.

## Investigation steps

### 1. Verify each witness can see before trusting what it says

Before collecting on any host, confirm its audit policy records successful
logons at all (see Windows Audit Blindness Triage). A host with
Failure-only Logon auditing reports zero logons *while the principal is
logged on to it* — the walk would read that as "the identity never went
here." Record the visibility state alongside every hop; a hop through a
blind witness is a gap in the path, not evidence of absence.

### 2. Collect the logon edges per host

On each host in the walk, pull the 4624 logons for the tracked principal
(target user name matches, not subject — a SYSTEM service touching the
user's profile is not the user logging on), with source IP, logon ID, and
logon type. Pull 4648 explicit-credential events where the subject is the
principal: these are the hops *out* — the identity was used to reach
another machine with new credentials. 4672 events (special privileges)
mark which logons carried administrative rights; those are the logons that
can install persistence.

Cap per-host collection (a fixed row limit per question, oldest-first) so
one noisy host cannot consume the walk budget.

### 3. Follow the hops under a distributed budget

A 4648 whose target server resolves to another estate host is an edge:
continue the walk there with a child budget one shallower than the parent.
The budget travels across the whole walk, not per host — this is what stops
a fan-out from becoming a worm. Never revisit a host already visited; a
cycle is a finding (the identity is pivoting through the same machines),
not a reason to keep walking.

### 4. Terminate honestly

The walk ends in one of exactly four ways, and the difference decides how
the result may be used:

- **origin** — the oldest logon of the chain came from a source outside
  the estate (a workstation, a VPN range, an unknown IP). High confidence:
  the entry point is the patient-zero candidate.
- **retention-boundary** — the relied-upon logon sits at the oldest event
  the host still holds; anything earlier has rotated away. Low confidence:
  the walk cannot claim an origin it cannot see past. Widen the window or
  pull central logs before concluding.
- **blind-witness** — a host in the chain cannot see its own logons (audit
  blindness). The path has a hole; the origin is unknowable from telemetry.
- **no-signal** — a host answered with no logons for the principal: the
  walk ends without an origin, which is a finding about the telemetry, not
  proof the identity stayed put.

### 5. Join the walk into a story and grade it

Order the hops by time (after checking clock skew — a host minutes off
makes the timeline lie). For each hop record: source, destination, logon
type (network, interactive, service), whether it carried admin rights, and
the visibility state of the host. Then grade the whole path: walks ending
in **origin** with full visibility are actionable; walks ending in
**retention-boundary** or **blind-witness** are leads whose confidence
label must survive into any report.

# Output

## Action
**report** — the walk path (host sequence, timestamps, logon types, admin
rights per hop) with its termination label and confidence; the patient-zero
candidate when termination is origin; the specific telemetry gaps (blind
witnesses, retention walls) that bound what can be known.

## Target
The walked identity and the hop chain — with the entry-point source and the
gaps labeled as gaps, never smoothed over.

## Evidence
Per-host 4624/4648/4672 collections with their visibility state, the walk
budget as consumed, the clock-skew check per host, and the termination
label with the reasoning that produced it.

## Reasoning
The mechanism, not the measurements: an identity's movement is recorded as
a chain of logons and explicit-credential hops, so reconstructing movement
is graph-walking — and the honest version of that walk spends as much
effort proving what it *cannot* see (blind witnesses, rotated logs, budget
exhaustion) as it spends collecting hops, because an overclaimed origin
sends responders to the wrong host.
