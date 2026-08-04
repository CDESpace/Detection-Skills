---
name: Cloud Security Control Evasion
description: Triage a cloud control-plane alert where an actor weakens or blinds
  the account's own security and visibility — deleting or suspending logging
  such as CloudTrail and flow logs, disabling detection tooling such as
  GuardDuty, Security Hub, or Defender, or suppressing findings. Reads the actor
  and the kind of change to tell a change-managed reconfiguration apart from an
  unexpected actor switching the account's eyes and ears off, and decides
  escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - defense-evasion
    - logging
    - detection-tampering
---

# Triage Steps

This class fires on actions that touch logging and detection controls — and those controls get edited, re-tuned, and re-applied all day by automation and admins doing legitimate work, so a control changing is not the signal. The signal is who touched it and whether they adjusted it or destroyed it: attackers blind the account before they act, so a control going fully dark is one of the higher-stakes shapes in this domain, but a routine re-config that leaves the control intact is not. Triage here is reading that difference and deciding whether the change looks like managed operations or like someone clearing the way — escalate or dismiss. This class turns on blinding the account's visibility — disabling or deleting the logging and detection configuration itself, the trail, the detector, the flow-log setup — distinct from breaking data protection or destroying data, which is a different class. Deleting the trail or stopping logging is this class; a destructive wipe of the store that holds the logs — mass-deleting the objects in the audit-log bucket or vault — is a data wipe that belongs to the destruction class by its activity.

Start from this detection's track record on this actor and control — a re-tuning rule that fires whenever the detection owner adjusts thresholds and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a hard delete of the only audit trail by an unexpected actor) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **The control destroyed, not adjusted.** A delete or hard disable rather than a documented re-config: `DeleteTrail`, `StopLogging`, `DeleteDetector`, `DeleteFlowLogs`, disabling Security Hub. Re-tuning leaves the control running; tearing it down removes the record entirely.
- **An actor that shouldn't be touching it.** The change comes from an actor not on the approved-admin or automation list, or one that has never managed this control — a compute or user identity disabling the audit trail, not the CI role that owns it. The identity directory (Graph/Okta users, directory-roles, service-principals) tells you which kind of identity you are looking at.
- **The account's only eyes go dark.** The action hits the primary or sole logging path or the main detection tooling — `PutEventSelectors` narrowing the trail to nothing, suppressing all findings — leaving no fallback record, rather than one of several redundant sinks. The resource posture (Wiz high-business-impact, public-exposure) shows what that coverage was protecting.
- **It clusters with other moves.** The same actor in the same window also makes an IAM grant, pulls a secret, or changes another security control. A control going dark right before or after other control-plane activity by one actor is the strongest tell — that chain is what clearing-the-way looks like.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A known infrastructure-as-code or automation identity — including provider service-linked roles — or a confirmed admin acting inside a change or maintenance window.
- **It matches the baseline.** The same actor routinely manages this exact control; a logging sink reconfigured but left intact, a detection re-tuned by its owner, a firewall rule edited and re-applied by the CI role.
- **Adjusted, not destroyed.** The control was re-tuned or reconfigured and is still running, not deleted or hard-disabled, and another logging path or detection control still covers the account.
- **Broad rollout, not a single target.** The same reconfiguration lands across many accounts or regions on a managed cadence — the shape of policy rollout; clearing the way hits one account's controls.
- **Clean history.** Prior dispositions for a known-noisy reconfiguration rule on this actor and control closed benign, with nothing new in the change this time.

To confirm a lead instead of guessing, pull the thread: did the same actor make an IAM grant, pull a secret, or move data in the same window after the control went dark? Corroboration turns a suspicious disable into a confirmed one.

# Output

## Decision
- **escalate:** the primary audit trail or a detection control is deleted or hard-disabled by an actor not on the approved-admin/automation list, outside a maintenance window, or the change is a deletion rather than a documented re-config — especially when it chains with other control-plane activity by the same actor.
- **dismiss:** a known automation or confirmed admin reconfigures a control it normally manages, inside a change window, leaving it running and other coverage intact. A dismiss is a positive call that the change is benign, made with that context in hand — an actor you confirmed manages this control, a change window or re-tuning pattern you actually saw; an actor you couldn't resolve or a change record you couldn't find is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or a primary control is destroyed by an unexpected actor — escalate.

## Evidence
The actor and whether it is a confirmed admin, automation, service-linked, or unexpected identity; whether the action was a delete/disable or a reconfiguration; which control was touched and whether it is the account's primary one; change-window and baseline fit; prior dispositions for the rule; and any sibling control-plane activity by the same actor.

## Reasoning
Name the leads that decided it and how they stacked — a compute role calling DeleteTrail outside any window, then granting itself a policy, is escalate on its own; the CI role re-tuning a detection it owns inside a change window, with logging left intact, is dismiss.
