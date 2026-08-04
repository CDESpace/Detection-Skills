---
name: Identity Directory Reconnaissance
description: Triage an identity alert where the directory is read at volume or
  with tooling — tenant or directory enumeration bursts, user-list or workflow
  exports, attack-tool fingerprints, and sensitive admin reads via scripting or
  CLI. Reads the directory audit trail and the actor's baseline cadence to tell
  sanctioned automation reading at its normal rate apart from a scripted
  enumeration burst staging an attack, and decides escalate or dismiss. Boundary
  — this skill owns the act of reading; a follow-on privilege change or
  app/device registration is cited only as chaining evidence.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - discovery
    - enumeration
    - offensive-tooling
---

# Triage Steps

This class fires on reads of the directory — bulk user lists, group memberships, role assignments, workflow exports, scripted admin reads. The directory is read constantly and legitimately: governance scanners inventory it, log collectors pull from it, backups copy it, admins script reports, so volume alone is not the signal. The signal is whether this volume and this client fit the actor's normal pattern. An attacker maps the directory before acting — who is privileged, which accounts to target, where the trust lies — and that mapping looks like a sanctioned scan until you compare it to the baseline. Triage here is deciding: is this sanctioned automation reading at its normal cadence, or a scripted enumeration burst staging an attack?

Begin with this detection's track record and the actor's baseline — an allowlisted service account reading at its usual rate, always closed benign, starts the call near dismiss — then read the audit trail for the leads below. None is required on its own; they stack, and a single strong one (an attack-tool fingerprint, enumeration that immediately precedes a grant) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A burst from a new or scripted client.** High-volume directory or user reads packed into a tight window from a client ID or app the actor has never used — hundreds of Graph `/users`, `/groups`, `/directoryRoles` reads in seconds, far above this actor's norm. A **malicious or suspicious reputation verdict on the source IP** behind the burst sharpens it.
- **An attack-tool fingerprint.** A user-agent, client ID, or call pattern matching known enumeration tooling — the cadence and endpoint mix of a recon framework rather than a steady governance scan.
- **An exporter with no reason to.** A bulk user-list or workflow export run by an account that has no admin or reporting role anywhere in its baseline — an ordinary user suddenly pulling the whole directory; the identity directory flagging the caller among risky-users adds weight.
- **Recon right before action.** The enumeration sits immediately before a privilege change or a new registration — read the directory, then grant a role or enroll a device in the same window. The follow-on event is cited as chaining evidence here; that event is judged under its own alert.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **An allowlisted source at its usual rate.** The reads come from a sanctioned scanner, identity-governance service, log collector, or backup account already on the allowlist, at the volume and cadence it always runs.
- **A scheduled export on its cadence.** A recurring export whose timing and size match the baseline — the same report that runs every week, on schedule.
- **Admin scripting from a known host.** Scripted reads from a recognized automation host inside a maintenance window, by an actor whose role includes them.
- **A service account, not an interactive user.** The reads come from a service principal whose job is exactly this — the identity directory (Graph/Okta users) confirms the account type — matching its standing pattern, not a person's interactive session suddenly enumerating.
- **Clean history.** This rule has closed benign on this actor before for the same recurring read, with nothing new in the volume or client this time.

To confirm a lead instead of guessing, pull the thread: after the read burst, did the same actor grant a role, register a device, or sign in to a freshly-mapped account in the same window? Corroboration turns a suspicious enumeration into a confirmed recon-before-action.

# Output

## Decision
- **escalate:** a high-volume burst from a new or scripted client, an attack-tool fingerprint, an export by an account with no reason to run it, or enumeration immediately preceding a privilege change or registration — especially two together, or any one with a directory change following it.
- **dismiss:** an allowlisted scanner or governance/backup account at its usual cadence, a scheduled export on its baseline, or admin scripting from a known host inside a window explains it. A dismiss is a positive call that the reads are benign, made with that context in hand — an allowlist entry you found for the source, a cadence you matched to its baseline; an account you couldn't identify or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when a burst comes from a new interactive actor, or the benign context is missing or you're unsure, escalate.

## Evidence
The read volume and cadence vs this actor's baseline, whether the client or account is allowlisted, any attack-tool fingerprint, service-account vs interactive actor, any follow-on privilege or registration event, and prior dispositions for this rule.

## Reasoning
Name the leads that decided it and how they stacked — a new interactive account running an enumeration burst with a recon-tool user-agent, then adding itself to a role, is escalate on its own; an allowlisted governance scanner running its weekly inventory at its usual rate is dismiss.
