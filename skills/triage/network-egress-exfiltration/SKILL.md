---
name: Network Egress Exfiltration
description: Triage a network alert where data leaves in an exfiltration- or
  payload-retrieval-shaped flow — large outbound volume to external IPs,
  sensitive-file egress such as keys and certificates, and suspicious downloads
  like script pulls or double-extension lures. Reads flow records and firewall
  logs for the destination, the outbound volume against the source's baseline,
  and the data's sensitivity to tell a sanctioned backup or SaaS sink apart from
  data heading somewhere it should not, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - network
    - exfiltration
    - data-egress
    - download
---

# Triage Steps

This class fires on the volume, sensitivity, or destination of data movement — gigabytes heading outbound, sensitive files leaving, a download with a lure-shaped name. The trouble is that the same gigabytes are routine to an approved cloud-storage endpoint and alarming to an unknown external IP, so the volume alone is not the signal. The signal is where the data is going and whether that fits the source's normal job. Exfiltration is the payoff stage of an intrusion, so triage here is reading the destination and the baseline together and deciding whether this is a backup doing its work or someone moving data out. The core question is whether this is a sanctioned backup or SaaS sink doing its normal job, or unusual volume heading to a bad or unknown destination. This class turns on volume and destination — how much left and where it went — and owns that call even when the channel also looks covert; a flow whose signal is that the remote end is an anonymizer or known-bad turns on the remote end instead.

Begin with this detection's track record on this source and destination — a rule that fires nightly on a server's backup job to the same cloud endpoint and is always closed benign starts the call near dismiss — then read the flow and firewall data for the leads below. None is required on its own; they stack, and a single strong one (multi-GB outbound from a workstation to an unknown external IP) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **An unsanctioned external destination.** A large outbound transfer to an external IP that is not a recognized backup or SaaS sink — a raw IP or a never-seen address. A **malicious or suspicious reputation verdict on the destination** makes an unfamiliar endpoint decisive; bytes-out far exceeding bytes-in to an endpoint nobody recognizes is the core signal.
- **Volume unusual for the source's role.** A workstation pushing multi-GB outbound, or any source moving far more than its baseline shows. The asset inventory (Axonius, managed-devices) tells you whether the source is a user endpoint — which pulls far more than it pushes — or a host whose job is moving data.
- **Sensitive data or sensitive source.** The egress carries keys, certificates, or regulated data, or the data-security context flags the store the source first read (Cyera datastores, Wiz high-business-impact) before sending volume out. Off-hours timing, or egress that clusters with prior recon or access on the same host, adds weight.
- **A lure-shaped download that ran.** An inbound pull of a script or a double-extension file (`invoice.pdf.exe`) with downstream activity on the host after it — a retrieval that landed and executed.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A recognized sink destination.** The external IP is the documented backup target, cloud-storage endpoint, or approved-SaaS range — where this data is supposed to go — and its reputation is known or clean.
- **Volume matches the source's baseline.** The outbound size and cadence fit a known sync or backup job the baseline already shows for this source, with nothing new this time.
- **A sanctioned pipeline or service account.** The source is a data-pipeline host or service account whose role is to move this volume, and the transfer fits that role.
- **Clean history.** This rule has closed benign on this source or destination before, with nothing new in the destination or volume this time.

To confirm a lead instead of guessing, pull the thread: in the same window, did the source first read from a sensitive internal store before sending out, and did the outbound flow actually complete, bytes-out matching the read? A staged read followed by a completed push to an unknown endpoint is exfiltration confirmed.

# Output

## Decision
- **escalate:** an unsanctioned destination with a bad or unknown reputation, volume unusual for the source's role heading somewhere that is not its recognized sink, sensitive-data egress, or a lure-shaped download that ran — especially two together, or any one with a sensitive-store read preceding a push to an unsanctioned or unknown destination.
- **dismiss:** a recognized backup, cloud-storage, or approved-SaaS sink matching a known sync job, or a corroborated pipeline or service account whose role is to move this volume, explains it, and the transfer goes to that recognized destination — a larger-than-usual day to the same sink, a weekly full backup or a period-end export, still fits. A dismiss is a positive call that the egress is benign, made with that context in hand — a sink you recognized, a baseline you actually saw; a destination you couldn't identify or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or unusual volume of sensitive data heads to an unknown destination — escalate.

## Evidence
The destination, whether it matches a recognized sink, and its reputation; whether the outbound volume fits the source's baseline; the sensitivity of the data moved and whether the data-security context flags the store; the source's role from the asset inventory; the timing; and how this rule was handled on this source or destination before.

## Reasoning
Name the leads that decided it and how they stacked — multi-GB of sensitive data from a workstation to an unknown external IP off-hours is escalate on its own; a server's nightly backup volume to its documented cloud endpoint is dismiss.
