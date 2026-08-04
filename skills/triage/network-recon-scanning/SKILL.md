---
name: Network Recon Scanning
description: Triage a network alert where one source fans out across many hosts
  or many ports — port and service scans, protocol probes, and host or segment
  sweeps. Reads flow records and firewall logs for direction, spread, and what
  the sweep reached to tell a sanctioned scanner apart from an internal foothold
  mapping the network, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - network
    - reconnaissance
    - port-scan
    - discovery
---

# Triage Steps

This class fires on fan-out traffic — one source touching many destinations or many ports, low bytes per flow. That shape is also what vulnerability scanners and asset inventory tools look like, so the fact that a sweep happened is not the signal. The signal is the story around it: where the source sits, what it reached, and whether scanning is that source's job. Recon is the prep step before lateral movement, so triage here is reading that story and deciding whether it looks like sanctioned scanning or like a host inside the network starting to map what it can reach. The core question is whether this is a known scanner or normal baseline, or an internal host quietly mapping its neighbors.

Begin with this detection's track record on this source and segment — a rule that fires daily on the same scanner range and is always closed benign starts the call near dismiss — then read the flow and firewall data for the leads below. None is required on its own; they stack, and a single strong one (an internal host sweeping a sensitive segment with flows completing) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Internal source scanning internally.** A workstation or server as the source IP, the destinations also on internal subnets — not inbound from the internet. One internal host opening flows to dozens of internal IPs on `:445`, `:3389`, `:22` in a short window is discovery from inside, the step before lateral movement.
- **The sweep reached sensitive assets.** The destinations are databases, management interfaces, domain controllers, or OT/ICS segments, and the resource posture flags them (Wiz sensitive-data, high-business-impact). Flows landing on `:1433`, `:3306`, hypervisor or switch management ports, or a segregated control network is recon with a target in mind.
- **The scan succeeded.** Flows completed and live services answered. Many completed low-byte flows to real listeners means the source now knows what is open — the sweep produced a map.
- **No baseline and no scanner match.** The source has never done this before and does not belong to any range that scans by design. The asset inventory (Axonius, managed-devices) tells you what the source is — a user laptop suddenly emitting a port sweep is the unusual case; a dedicated scanner appliance doing it nightly is not. A **malicious or suspicious reputation verdict on an external source** adds weight when the sweep comes in from outside.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A confirmed scanner identity.** The source IP belongs to the documented vulnerability- or attack-surface-scanning range, or a known asset-inventory host, whose whole job is to sweep, or an external source whose reputation is a known internet-wide scanner.
- **It matches the source's baseline.** This source has emitted the same sweep shape on the same cadence before as normal activity, and nothing about the targets or timing changed this time.
- **Fleet-wide maintenance, not single-target.** The sweep lines up with a scheduled scan window or a broad inventory pass across the environment — the shape of operations, which scans everything; an intrusion sweeps from one unexpected host.
- **Clean history.** This rule has closed benign on this source or segment before, with nothing new in the direction or targets this time.

To confirm a lead instead of guessing, pull the thread: in the same window, did one of the swept hosts answer with a real session — a completed flow carrying bytes to a service the source had just probed? A probe that turns into a connection is recon turning into access.

# Output

## Decision
- **escalate:** an internal source sweeping internal hosts, a sweep that reached sensitive assets, a scan that succeeded against live services, or an unknown source with no scanning baseline — especially two together, or any one with a real follow-on session after it.
- **dismiss:** a confirmed scanner range, a baseline match, or a scheduled maintenance pass explains it — a corroborated authorized scanner (range, schedule, and scope confirmed) accounts for internal-to-internal sweeps, reaching sensitive segments, and the credentialed sessions a scan opens — and nothing follows that its authorized pattern does not explain. A dismiss is a positive call that the sweep is benign, made with that context in hand — a scanner range you matched, a sweep shape and cadence the baseline actually shows; a source you couldn't identify or a scan schedule you couldn't confirm is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or an internal sweep hits sensitive targets with no corroborated scanner behind it, or a probe turns into a targeted session beyond that pattern — escalate.

## Evidence
The scan's direction and source, whether the source matches a known scanner range or maintenance window and its reputation, the source's role from the asset inventory, the sensitivity of the targets reached and whether the resource posture flags them, and how this rule was handled on this source or segment before.

## Reasoning
Name the leads that decided it and how they stacked — an internal host with no scanner standing sweeping a database segment with flows completing is escalate on its own; a documented scanner range doing its nightly pass on its usual cadence is dismiss.
