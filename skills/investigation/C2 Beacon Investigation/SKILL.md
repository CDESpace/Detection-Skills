---
name: C2 Beacon Investigation
description: |-
  Investigate an escalated command-and-control beaconing alert. Confirms
  the periodicity and destination are really C2, scopes which hosts and
  processes are beaconing, identifies the implant or framework where it
  can, and checks for hands-on-keyboard follow-through before returning a
  verdict with containment actions.
type: investigation
version: 1.0.4
metadata:
  author: ghostbyte
  labels:
    - network
    - c2
    - malware
    - endpoint
---

# C2 Beacon Investigation

Runs on alerts escalated by triage (see `network-anonymized-c2-traffic`):
a host showed regular, low-variance outbound connections to a destination
that triage judged unlikely to be a legitimate service. Triage established
the beacon shape is anomalous; investigation establishes whether it is a
real implant, which processes and hosts it lives on, and what the operator
has done through it. The question is not "did something beacon" — it did —
but "what is talking, to whom, and has an operator acted."

## Inputs

- The escalated alert (source host, destination IP/domain, interval and
  jitter, first-seen, byte volumes) and the triage report.
- Network flow/proxy logs and endpoint process telemetry for the host.
  DNS resolution logs and threat-intel reputation for the destination.
  Confine the sweep to a bounded window — from first-seen to now is usually
  enough.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Beacon confirmation — signal A

Re-derive the periodicity from raw flows: interval, jitter, and request
size regularity. **Signal A fires** when the cadence is machine-regular
(fixed interval with small jitter, near-identical request sizes) and
persists across long idle periods no human browsing would produce.
A destination that is a CDN, software-update endpoint, or telemetry
service with clean reputation weakens it — regularity alone is not C2.

### 2. Destination attribution — signal B

Resolve the destination: current and historical DNS, hosting ASN,
certificate, domain age, and reputation. **Signal B fires** on a newly
registered domain, a known-malicious or default C2 certificate (self-signed,
known framework fingerprints), fast-flux resolution, or infrastructure that
threat intel ties to a named family. Record whether other hosts in the
environment talk to the same destination.

### 3. Process and host scoping — signal C

On the beaconing host, tie the flows to a process and its parent chain.
**Signal C fires** when the beacon originates from an unexpected process
(a LOLBin, a process running from a temp/user-writable path, an unsigned
binary, or a browser child that shouldn't have network autonomy) rather
than a sanctioned application. Sweep the environment for other hosts with
the same process or the same destination to establish spread.

### 4. Operator activity — signal D

Look for hands-on-keyboard follow-through around the beacon: discovery
commands, credential access, new persistence, lateral connections, or
data staging on the beaconing host. **Signal D fires** when the beacon is
accompanied by interactive tradecraft — this separates a live operator
from a dormant or automated implant and is the strongest single signal.

## Verdict rule

- **malicious:** signal B or C plus either A or D — attributed bad
  infrastructure or a suspicious process that is genuinely beaconing, and
  especially any beacon with operator activity (D). D alone, with a
  confirmed beacon, is malicious regardless of attribution.
- **suspicious:** a confirmed beacon (A) to unattributed infrastructure
  with no clear process explanation, where B/C/D can't be established but
  benign use can't be shown either.
- **inconclusive:** the beacon can't be reconfirmed from raw data, or logs
  needed to attribute the destination or process are missing.
- **benign:** the cadence resolves to a sanctioned application talking to a
  clean, attributable service — telemetry, update check, monitoring agent —
  matching that host's baseline, with no suspicious process and no operator
  activity.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it.

### Recommended actions
When not benign: isolate the beaconing host(s), block the destination at
egress and DNS, preserve the implicated process and its artifacts for
forensics, hunt the environment for the same destination and process, and
rotate any credentials the host handled. Scale to the spread found in
step 3.

### Evidence
The confirmed cadence and idle persistence, destination attribution
(DNS/ASN/cert/reputation/domain age), the beaconing process and its chain,
the list of other affected hosts, and any operator activity observed.

### Reasoning
Name the signals and how they stacked — a fixed-interval beacon to a
two-day-old domain from an unsigned temp-path binary, followed by discovery
commands and a new scheduled task, is malicious; a regular call to a
reputable update service from the vendor's signed agent is benign.
