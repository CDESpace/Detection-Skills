---
name: Identity Control Tampering
description: Triage an identity alert where a security guardrail is changed or
  access is removed — conditional-access deleted or weakened, MFA disabled,
  sign-on rules or zones widened, federation, domain, or cross-tenant trust
  added, log-stream tampering, and destructive actions such as admin-role
  revoke, token revoke, or app deactivation. Reads the directory audit trail to
  tell a legitimate admin reconfiguring or tightening a control apart from a
  guardrail being torn down to clear the way for abuse, and decides escalate or
  dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - defense-evasion
    - conditional-access
    - federation
---

# Triage Steps

This class fires on changes to the identity security fabric — a conditional-access policy edited, MFA settings flipped, a trust added, an account or app torn down. Admins reconfigure these controls all the time: they tighten policy, add requirements, retire stale apps, decommission integrations, so the fact that a control changed is not the signal. The signal is the direction of the change and who made it. Weakening and tightening look almost identical in the raw audit event — same policy, same actor field — but mean opposite things, so a "control updated" alert is the defender reading which way the change pointed. Triage here is deciding: did an admin legitimately reconfigure or tighten a control, or is a guardrail being torn down to clear the way for later abuse?

Begin with this detection's track record on this config — a policy that is churned routinely by a known admin and always closed benign starts the call near dismiss — then read the audit trail for the leads below. None is required on its own; they stack, and a single strong one (MFA turned off, a new external trust added) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A control weakened or removed.** A conditional-access policy `deleted` or scoped down — the conditional-access-policies record shows who it covered, so you can see what protection was lost — MFA disabled for a user or group, a sign-on rule loosened, a network zone widened to include new ranges, or a log stream paused. The change makes the next attack easier, not harder — that direction is the tell.
- **Trust added that lets outsiders in.** A new federation realm, a new verified domain, or cross-tenant access settings that let external tokens be minted or external identities sign in — `Add domain`, `Set federation settings`, a new cross-tenant inbound trust. This opens a door rather than closing one; a **malicious or suspicious reputation verdict on the added domain or realm** makes it decisive.
- **A mass revoke or teardown by the wrong actor.** Admin roles revoked, tokens revoked at scale, or critical apps deactivated by an actor with no offboarding or decommission behind it — anti-recovery, cutting off the people who would respond.
- **Made by an actor who should not touch it.** The weakening or teardown comes from a non-admin — the identity directory (role-assignments) shows no admin standing behind the account — a service principal, or an account with no history of identity-config changes, and no change record sits behind it.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A confirmed admin tightened it inside a window.** An identity admin whose role includes this change made it in a known maintenance window, and the change adds a requirement or narrows a zone rather than removing one.
- **The change tightens, not loosens.** A new MFA requirement added, a policy scoped to more users, a zone narrowed — the direction points toward more protection.
- **An established integration explains it.** A directory-sync or vendor integration whose trust or federation change matches its known, already-present setup.
- **A user fixed their own access.** A self-service MFA reset by the owner from a trusted, recognized device — not an admin disabling MFA for someone else.
- **A teardown that matches a record.** A revoke or deactivation that lines up with an HR offboarding or a planned decommission already on the books.

To confirm a lead instead of guessing, pull the thread: after the control changed, did a sign-in that the old policy would have blocked succeed, or did an external token appear, in the same window? Corroboration turns a suspicious config change into a confirmed teardown.

# Output

## Decision
- **escalate:** a control weakened or removed, a trust added that lets external access in, or a mass revoke/deactivation by an actor with no offboarding behind it — especially two together, or any one with a previously-blocked sign-in succeeding after it.
- **dismiss:** a confirmed admin tightening a control inside a known window, a change that adds protection, an established sync/integration, or a self-service MFA reset from a trusted device explains it. A dismiss is a positive call that the change is benign, made with that context in hand — an admin whose standing you confirmed, a maintenance window or offboarding record you actually saw; an actor you couldn't resolve or a change record you couldn't find is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or conflicting — on a weakening or teardown especially — or you're unsure, escalate.

## Evidence
The direction of the change (weaken vs tighten), the actor's admin standing, any change-window or known-integration baseline, for destructive actions any offboarding or decommission record, whether external trust was added and any reputation verdict on an added domain or realm, and prior dispositions for this rule.

## Reasoning
Name the leads that decided it and how they stacked — a non-admin deleting a conditional-access policy and then a blocked geo signing in is escalate on its own; a confirmed admin adding a new MFA requirement inside a maintenance window is dismiss.
