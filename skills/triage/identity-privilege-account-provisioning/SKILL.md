---
name: Identity Privilege Account Provisioning
description: Triage an identity alert where someone gains power in the directory
  — admin-role grants, accounts created and then privileged, external guests
  granted privilege, and a directory role or privileged group assigned to a
  service principal. Reads the directory audit trail to tell authorized admin
  changes and routine onboarding apart from someone handing power to themselves,
  a stranger, or a fresh account, and decides escalate or dismiss. Boundary —
  this skill owns the privilege an account holds; a consent grant, a secret
  added for an integration, a redirect URI, or a device enrollment is a
  foothold, not a directory-privilege grant.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - privilege-escalation
    - provisioning
    - service-principal
---

# Triage Steps

This class fires on privilege moving in the directory — a role assignment, a privileged-group add, a just-in-time activation, a standing role handed to a service principal. These are directory-provider events, read in the identity directory's own audit trail; a privileged-group change that originates on a domain controller or a host's security log is read at that host, not here. Granting access is everyday IT work: people get onboarded, admins delegate, projects spin up service accounts, so the grant itself is not the signal. The signal is who did it, who received it, and whether the normal approval path was followed. An attacker who lands one foothold reaches for durable privilege next, and they do it by skipping the path real changes go through. Triage here is reading the audit trail and deciding: is this an authorized change or routine onboarding, or did someone just hand power to themselves, a stranger, or a fresh account?

Begin with this detection's track record on this actor — a rule that fires whenever a known admin runs a recurring grant and is always closed benign starts the call near dismiss — then read the audit trail for the leads below. None is required on its own; they stack, and a single strong one (the actor granting their own account, privilege to a brand-new account) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **The grant points back at the grantor.** A self-grant — `Add member to role` where the actor and the target are the same identity — or two accounts that grant each other reciprocally. Real privilege changes flow from an admin to someone else, not to the admin's own account.
- **Power lands on a fresh or outside account.** A privileged-group add or role assignment to an account `created` minutes earlier, or to an external guest (a `#EXT#` / B2B identity) — the identity directory (Graph/Okta users) carries the target's account age and guest status. The created-then-immediately-privileged sequence is the classic shape.
- **It skips the approval path.** A grant that bypasses just-in-time or PIM activation in an org that uses it, or one made outside any change window with no approver and no ticket anywhere in the actor's history.
- **A standing directory role goes to a service principal.** A privileged directory role — Global Administrator, Privileged Role Administrator, or a role carrying directory-write — assigned to a service principal, a durable hold a password reset cannot evict. The consent that grants an app its API permissions, and the secret backing an integration, are foothold mechanisms judged on the app itself; the standing directory role handed to the principal is this class's.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A confirmed admin made it inside a window.** The actor is an identity admin whose role includes this grant — the identity directory (role-assignments, directory-roles) confirms that standing — and the change falls in a known maintenance window with an approver or ticket attached.
- **It matches the target's role record.** The grant lines up with the target's HR or job record as routine onboarding — a new hire getting the standard role their team holds.
- **It is an eligible activation, used as intended.** A just-in-time / PIM activation the actor is eligible for, scoped to the task and timed-out, not a permanent assignment.
- **A broad rollout by a known provisioning identity.** The same role or group change applied across many accounts on an onboarding or reorg cadence, or handed out by an established provisioning or identity-governance automation on its documented pattern — the shape of provisioning, which moves in batches to others; a self-serving grab hits one account, and automation provisions to others, it does not promote itself. Volume alone does not clear a privileged or admin-role grant — a batch of them still needs an authorization behind it.
- **Clean history.** This rule has closed benign on this actor before for the same recurring grant, with nothing new this time.

To confirm a lead instead of guessing, pull the thread: after the grant, did the newly-privileged account immediately use the power — read broadly across the directory, add another account, change a control — in the same window? Corroboration turns a suspicious grant into a confirmed escalation.

# Output

## Decision
- **escalate:** a self-grant, privilege to a brand-new or external account, a grant that skips the JIT/PIM or change path, or a standing directory role given to a service principal — especially two together, or any one with the new power used right after.
- **dismiss:** a confirmed admin granting inside a window with an approver or ticket, an onboarding match to the target's role record, an eligible scoped activation, or a known provisioning automation granting on its documented pattern explains it, and nothing skipped the path or self-targeted. A privileged or admin-role grant needs that positive authorization — a change record, a known provisioning identity, or a documented break-glass — to dismiss; daily volume or the actor merely being an admin is not on its own benign proof. A dismiss is a positive call that the grant is benign, made with that context in hand — an approver or ticket you actually saw, an onboarding record you matched to the target; an actor whose standing you couldn't confirm or a change record you couldn't find is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the actor equals the target, the target is fresh, a privileged grant has no authorization behind it, or the benign context is otherwise missing or you're unsure, escalate.

## Evidence
Whether the actor equals the target, the target's account age and internal/external status, the actor's admin standing, any approver/ticket/change-window context, whether it bypassed JIT/PIM, whether a service principal received a standing role, broad rollout vs single target, and prior dispositions for this rule.

## Reasoning
Name the leads that decided it and how they stacked — an actor adding their own account to a privileged role outside any window, then enumerating the directory, is escalate on its own; a confirmed admin onboarding a new hire to the standard team role inside a maintenance window is dismiss.
