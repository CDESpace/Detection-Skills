---
name: Network Anonymized C2 Traffic
description: Triage a network alert where an internal host talks to anonymizing
  or known-bad infrastructure over a covert channel — Tor and onion access,
  anonymizer exit nodes, known-C2 IPs and ports, DNS over odd ports, unknown
  protocols, and long-lived beacons. Reads flow records and firewall logs for
  the remote end, the protocol shape, and the beacon cadence to tell a
  sanctioned privacy tool apart from confirmed command-and-control, and decides
  escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - network
    - c2
    - tor
    - covert-channel
---

# Triage Steps

This class fires on the shape and destination of the channel, not on how much data moved — a flow to a Tor exit, a connection on a flagged C2 port, DNS running over a non-standard port, an unknown protocol, a steady periodic beacon. Those shapes also have benign sources: privacy-conscious users, sanctioned research, pentests, and oddly-built internal apps that the baseline already knows. So the channel alone is not the signal. The signal is the story around it: what the remote end is, which internal host opened it, and how the channel behaved. Command-and-control hides inside exactly these channels, so triage here is reading that story and deciding whether it looks like a tolerated tool or like a host phoning home. The core question is whether this is a sanctioned privacy or research tool, versus a malicious remote end reached from a server or critical asset. This class turns on what the remote end is — an anonymizer or known-bad reputation — and how the channel behaves; how much data moved is a data-egress reading, and a large outbound volume riding the channel is corroboration a tolerated-tool dismiss cannot clear.

Begin with this detection's track record on this host and remote end — a rule that fires on a workstation's tolerated privacy-browser use and is always closed benign starts the call near dismiss — then read the flow and firewall data for the leads below. None is required on its own; they stack, and a single strong one (a server beaconing to a malicious IP over a channel that stayed open) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A malicious remote end.** The destination carries a malicious or suspicious reputation verdict — a known-C2 or Tor-exit match, not merely an unknown address. An internal host opening a flow to a listed exit node or a flagged C2 port is the primary signal — a verdict against known infrastructure, not a guess.
- **A server or critical asset initiating it.** The internal side is a server, domain controller, or production system rather than a user workstation — the asset inventory (Axonius, managed-devices) tells you which. A server has no business opening Tor or unknown-protocol egress to the internet — workstations sometimes do, infrastructure does not.
- **A steady beacon.** Flows from the same host to the same remote end on a fixed interval — every 60s, every 5m — small and regular, against the host's baseline. Periodic same-size callbacks are how an implant checks in; real apps are bursty and event-driven.
- **Long-lived or two-way.** The channel opened, persisted, and carried traffic in both directions, or a Tor-sourced login succeeded — the covert channel is open and working.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A sanctioned source.** The activity traces to a documented privacy tool or an allowlisted application on a workstation where policy tolerates it, or to an authorized pentest whose engagement is positively corroborated — a confirmed scope, window, and source range. A corroborated engagement can account for a server source and a listed remote end; the label alone, or a flow that merely resembles a pentest, is not a dismiss.
- **It matches the host's baseline.** The "unknown protocol" or odd-port flow is one the baseline already shows as a known-benign internal app for that exact host pair, on its normal cadence.
- **A workstation, not infrastructure.** The internal side is a user endpoint where this is tolerated, the remote end's reputation is unknown rather than malicious or suspicious, and nothing else corroborates.
- **Clean history.** This rule has closed benign on this host or remote end before, with no malicious verdict on the remote end and nothing new in the cadence this time.

To confirm a lead instead of guessing, pull the thread: in the same window, is the cadence actually periodic across many flows, and did any of those flows carry a real two-way session? A single odd flow is weak; a regular beacon to a listed endpoint that stays open is C2 confirmed.

# Output

## Decision
- **escalate:** a malicious or suspicious verdict on the remote end, a server or critical asset initiating covert egress, a steady beacon cadence, or an open long-lived channel — especially two together, or any one with a confirmed two-way session.
- **dismiss:** a documented privacy tool or a baseline match for the odd protocol explains it and the remote end's reputation is not malicious or suspicious, or a positively corroborated authorized pentest, its scope and window confirmed, accounts for it — a corroborated engagement covers a server source or a listed remote end, since that is what red-team infrastructure looks like. A dismiss is a positive call that the channel is benign, made with that context in hand — a privacy tool you found documented, a host-pair baseline you actually saw; a remote end you couldn't identify or an engagement you couldn't corroborate is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or a server reaches a malicious endpoint, a beacon is present, or a large outbound volume rides the channel with no corroborated sanctioned cause — escalate.

## Evidence
The remote end and its reputation verdict against the known-C2 and Tor-exit lists, whether the internal side is a server or a workstation from the asset inventory, the beacon cadence against the host baseline, and how this rule was handled on this host or remote end before.

## Reasoning
Name the leads that decided it and how they stacked — a server beaconing on a fixed interval to a malicious C2 IP over an open channel is escalate on its own; a tolerated privacy browser on a user laptop on its known baseline is dismiss.
