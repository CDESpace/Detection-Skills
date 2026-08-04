---
name: Cloud Recon Secret Harvest
description: Triage a cloud control-plane alert where an actor reads broadly
  across the account — Describe/List sweeps across regions and services,
  subscription-wide enumeration bursts, mass reads from secret stores such as
  Secrets Manager, SSM, or Key Vault, and instance-password pulls. Reads the
  actor and the shape of the reading to tell a known inventory or posture
  scanner apart from a credential mapping its blast radius or harvesting
  secrets, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - discovery
    - credential-access
    - enumeration
---

# Triage Steps

This class fires on read-only API calls — Describe, List, GetSecretValue — and reads are cheap and constant, run all day by posture scanners, inventory tools, and the application service identities that legitimately consume those exact secrets. So the fact that something read is never the signal; a single fetch means almost nothing. The signal is the shape of the reading: how broad it is, how fast, and who is doing it. A credential validating what it can reach sweeps wider and faster than the actor's normal baseline. Triage here is reading that shape and deciding whether it looks like a routine scanner doing its rounds or someone casing the account — escalate or dismiss. This class turns on reading existing secrets and keys — the breadth and speed of the reads — distinct from creating a new credential or grant, which is a different class; a read that immediately precedes or feeds a credential creation by the same actor is corroboration that points at a real threat, not something the reader's identity waves off.

Start from this detection's track record on this actor and scope — a sweep rule that fires whenever the posture scanner runs and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a human key sweeping every region it has never touched) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Breadth the actor never shows.** Enumeration or secret reads spanning resources, services, or regions this actor never touches — `Describe*`/`List*` across every region at once, `GetSecretValue` walking an entire secret store. A credential mapping its blast radius reads everywhere; a normal consumer reads its own corner.
- **Burst velocity where a human clicks.** An automated cadence — hundreds of reads in seconds — from an identity that normally makes a few scoped calls by hand. The machine-speed pattern from a human actor is the tell.
- **A risky or new actor doing the reading.** A freshly created identity, a leaked-key candidate, or a human key behaving like a tool — an interactive identity running a region-wide sweep. The identity directory (Graph/Okta users, risky-users, service-principals) tells you how new the identity is and what kind it is; the actor type tilts hard here even before the breadth does.
- **High-value material, or reads next to other moves.** The sweep hits root or admin credentials, production database secrets, or signing keys — the data-security context flags what they guard (Cyera datastores, Wiz sensitive-data) — or the burst sits right next to an IAM grant or precedes data movement by the same actor. Casing that lands on the crown jewels, or chains into the next step, is the strongest shape.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it, and the reads fit its documented job.** A confirmed posture, inventory, or backup scanner sweeping as it always does, or a named secrets-consuming service identity reading the specific set it is provisioned to consume, on its documented cadence and within its baseline scope. The identity alone is not enough — a secrets consumer walking the whole store, beyond the corner it normally reads, is not ruled out by being automation, and a first-time-seen pattern for this identity is not proof it is benign.
- **It matches the baseline.** The same actor, scope, and read volume have appeared here before as normal activity; volume well inside this actor's normal range.
- **Scoped, not a sweep.** A single named fetch by an engineer in context, or reads confined to the resources and region this actor owns — not a cross-region, cross-service walk.
- **Broad fleet pattern, not one actor casing.** The same read pattern runs on a fixed cadence across the account as scheduled scanning — the shape of inventory tooling, which sweeps by design; a credential casing the account is a single off-baseline actor.
- **Clean history.** Prior dispositions for the same actor-and-scope closed benign, with nothing new in the breadth or velocity this time.

To confirm a lead instead of guessing, pull the thread: did the same actor make an IAM grant, share a snapshot, or pull a volume in the same window after the reads? Corroboration turns a suspicious sweep into a confirmed one.

# Output

## Decision
- **escalate:** enumeration or secret reads span resources or regions the actor never touches, show burst velocity where a human normally clicks, or the actor is newly created, a leaked-key candidate, or a human key behaving like a tool — especially when the reads hit high-value material or chain into a grant or data movement.
- **dismiss:** a confirmed posture/inventory/backup scanner, or the service identity that legitimately consumes those secrets, reads at a steady baseline within its normal scope and volume. A dismiss is a positive call that the reading is benign, made with that context in hand — a scanner you confirmed, a scope and cadence you actually saw in its baseline; an actor you couldn't resolve or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or the breadth or velocity is off-baseline and the actor is risky — escalate.

## Evidence
The actor and whether it is the owning service, a confirmed scanner, a human, or a new/risky identity; the breadth (regions, services, secrets touched) versus baseline; the read volume and velocity; the sensitivity of what was read; and any adjacent grant or data movement by the same actor.

## Reasoning
Name the leads that decided it and how they stacked — a leaked-key candidate sweeping Describe across every region then pulling production database secrets is escalate on its own; a known posture scanner running its usual List sweep within baseline is dismiss.
