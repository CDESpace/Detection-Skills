---
name: Application Control Policy Tampering
description: Triage a SaaS or tenant alert where a security control is weakened
  or admin control is seized — MFA, audit logging, or secret-scanning turned
  off, a security or tenant or cross-tenant policy edited, a tenant-admin or
  impersonation role granted, or a risky OAuth app or integration added. Reads
  the actor's identity, history, and the change window to tell routine admin and
  platform self-maintenance apart from an unexpected actor turning a protection
  off or handing out durable privilege, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - defense-evasion
    - privilege-grant
    - policy-tampering
---

# Triage Steps

This class fires on actions that are normal admin work by themselves — disabling MFA during a migration, editing a tenant policy, granting an admin role, installing an integration. Someone does each of these legitimately every week, so the fact that one happened is not the signal. The signal is who did it and whether they belonged to the change: an attacker who has taken an account weakens controls and grants themselves privilege using the same audit-log events a real admin generates. Triage here is reading the actor and the timing and deciding whether this is the right person at the right time or an unexpected actor weakening the app. This class owns the tenant-side change itself — the control edit, the OAuth or integration consent grant, the role grant — distinct from a delivered lure that may have prompted a user to approve it, which is judged on the delivery.

Begin with this detection's track record on this actor and tenant — a rule that fires whenever the platform team runs maintenance and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a self-grant of admin, MFA turned off by someone not on the admin team) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A protection turned off by the wrong actor.** A `disable`/`update` on a security setting by someone outside the admin team for that control: `Disable Strong Authentication`, `Set-OrganizationConfig AuditDisabled=$true`, secret-scanning or branch-protection switched off on a repo by a non-owner. Turning a protection off leans escalate; turning one on is usually hygiene.
- **A self-grant or fresh-account elevation.** The grantor and grantee being the same actor (`Add member to role` where actor == target), or a just-created account that received a token and then elevated. Real role grants are normally handed out by an existing admin to someone else, not claimed by the actor for themselves.
- **A risky integration from an unverified source.** An OAuth app or third-party integration consented in from an unverified or unofficial publisher, asking for broad tenant-wide scopes: `Consent to application` with `Directory.ReadWrite.All` or full-mailbox access, an unlisted app rather than one from the org's known catalog. A malicious or suspicious reputation verdict on the app's publisher domain sharpens the call. The apps-and-tokens context (service-principals, oauth2-permission-grants) tells you whether the app and its grants are already established in the tenant.
- **A tenant or cross-tenant policy edit that widens trust.** A change that loosens who can act or adds a trusted partner tenant — a conditional-access policy weakened, a cross-tenant access setting opened, an impersonation role granted. Widening trust is the durable-access move attackers reach for after taking an admin.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A confirmed admin whose role fits.** The actor is a known IT or platform admin — the identity directory (role-assignments, directory-roles) confirms their standing — whose role and prior history include this exact change. A self-grant is the exception: confirmed-admin standing alone does not dismiss it, and it stays escalate-reachable unless a documented break-glass record accounts for this specific elevation.
- **A known automation identity.** A first-party vendor backend account or a documented infrastructure-as-code service account with a steady baseline of these same changes — the platform or pipeline maintaining itself.
- **It matches the baseline and window.** The same control, the same actor, the same kind of change has run here before inside a known maintenance or change window.
- **The change is removal, not seizure.** An admin role being removed as part of offboarding, or an integration coming from a source the org already trusts and runs broadly, its publisher's reputation known or clean.
- **Clean history.** This rule has closed benign on this actor before, with nothing new about who acted or what was touched this time.

To confirm a lead instead of guessing, pull the thread: did the same actor make further control changes, grant more roles, or sign in from an unusual place in the same window? Corroboration turns a suspicious admin action into a confirmed one.

# Output

## Decision
- **escalate:** a protection turned off by an actor not on the admin team for that control, a self-grant of admin, a fresh or token-claiming account that elevated, a risky integration from an unverified source, or a policy edit that widens trust — especially two together, or any one with more control changes after it.
- **dismiss:** a confirmed admin or known automation identity, acting inside a known window with a baseline match, explains it, and nothing widens trust or hands out durable privilege — or a self-grant is accounted for by a documented break-glass record. A dismiss is a positive call that the change is benign, made with that context in hand — an admin you confirmed in the directory, a window or baseline you actually saw the change fit; an actor you couldn't resolve or a window you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or an unknown actor weakens a load-bearing control, or a self-grant has no documented break-glass record — escalate.

## Evidence
The control or policy touched and the toggle direction, the actor and whether they are a confirmed admin / known automation / newly created, whether grantor equals grantee, the change window, the integration's source and its publisher's reputation, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — a fresh account that claimed a token and then turned off MFA is escalate on its own; a known platform service account editing the same policy on its usual cadence is dismiss.
