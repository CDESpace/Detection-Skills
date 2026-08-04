---
name: Application Data Exfiltration Oversharing
description: Triage a SaaS or collaboration alert where data leaves or is
  overshared from a repository — bulk download or upload, an external or
  anonymous share link, third-party sharing, inbox auto-forwarding including
  forward-and-delete, a repo fork or transfer, or a mass export. Reads the
  destination, the actor, and the volume against that actor's baseline to tell
  documented backup, migration, and pipeline movement apart from an unexpected
  external share or off-baseline move, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - exfiltration
    - oversharing
    - collection
---

# Triage Steps

This class fires on actions people do all day — download, upload, share, forward, export. The fact that content moved is not the signal; backups, migrations, and ordinary collaboration move content constantly. The signal is where it went and whether the volume and timing fit who moved it: an attacker collecting data out of an account uses the same download and share events a normal user does, just to a destination that leaves the org or a volume that breaks the actor's pattern. Triage here is reading the destination and the actor and deciding whether this is a documented backup or pipeline movement or an unexpected leak. This class turns on an internal actor moving data out — distinct from an external client pulling data in through an exposed app surface, which is judged on the request itself.

Begin with this detection's track record on this actor — a rule that fires every night when the backup job runs and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (an anonymous link on an executable, an external forward-and-delete rule) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A destination that leaves the org.** Content going to an external recipient, an anonymous link, a personal repo, an unsanctioned app, or an unmanaged device: `AnonymousLinkCreated`, a share to a `@gmail.com` address, a repo `Transfer` to a personal account. A malicious or suspicious reputation verdict on the destination domain makes an unfamiliar target decisive. One pattern overrides volume entirely — an anonymous share link on a script or executable escalates no matter how small, because that is a delivery setup, not a data leak.
- **An inbox rule forwarding outside.** An auto-forward to an external address, especially forward-and-delete: `New-InboxRule ForwardTo <external> DeleteMessage=$true`. This is almost never legitimate and is a classic mailbox-persistence move.
- **Volume far over this actor's baseline.** A bulk download or export many times this actor's normal day, or at an hour they never work: hundreds of files pulled from a drive by a role whose baseline is a handful, a full mailbox export off-hours. Volume only means something against who this is and when, not as a raw number — and it weighs more when the data-security context flags the store as holding sensitive data.
- **A high-risk actor moving data out.** A terminated or offboarding user — a status the identity directory (Graph/Okta users) confirms — or a newly created account, doing any meaningful download or share out — the actor who should be moving the least is moving the most.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A documented automation identity to a known sink.** A named service or ETL account doing scheduled bulk movement to a sink documented for it and that it always uses — an internal store or a sanctioned external destination named in its configuration. An external sink does not by itself break this rule-out when the identity and the sink are both documented; an external destination that is not documented for the actor does not qualify.
- **A destination inside the org's own trusted domains.** Sharing to recipients on org-owned domains or a known internal repository, not an external or anonymous target, and the destination's reputation is known or clean.
- **It matches the actor's baseline.** The same volume, kind of move, and time of day this actor does as normal work — a large download from someone whose normal day is large downloads.
- **A broad, sanctioned rollout, not a single target.** A backup, DLP, or migration job moving content for many users on a known cadence — the shape of tooling, not one account exfiltrating.
- **Clean history.** This rule has closed benign on this actor before, with the same destination and volume and nothing new this time.

To confirm a lead instead of guessing, pull the thread: did the same actor create more external shares, set more forwarding rules, or download from other repositories in the same window? Corroboration turns a suspicious share into a confirmed one.

# Output

## Decision
- **escalate:** an external or anonymous destination, an external auto-forward, volume far over this actor's baseline or off-hours, or a high-risk actor moving data out — and an anonymous link on a script or executable escalates on its own.
- **dismiss:** a documented automation identity moving to a sink documented for it — an internal store or a sanctioned external destination named in its configuration — or a baseline match within trusted domains, with nothing off-baseline. A dismiss is a positive call that the move is benign, made with that context in hand — a sink you matched to the actor's documentation, a baseline you actually saw the volume fit; a destination you couldn't place or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or the destination is external and not documented for the actor, or anonymous, or the actor or volume is off baseline — escalate.

## Evidence
The destination (external / anonymous / internal-trusted / unmanaged) and its reputation, the volume against this actor's baseline and the time of day, the content sensitivity and whether the data-security context flags the store, the actor type (automation / human / terminated / new), the forwarding-rule shape, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — a terminated user's account setting a forward-and-delete rule to a personal address is escalate on its own; a documented ETL account doing its nightly export to the same internal sink is dismiss.
