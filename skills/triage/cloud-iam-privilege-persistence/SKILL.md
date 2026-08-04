---
name: Cloud IAM Privilege Persistence
description: Triage a cloud control-plane alert where an actor grants standing
  access or plants a lasting foothold — attaching admin or wildcard policies,
  adding a user to a privileged role or group, creating IAM users, access keys,
  login profiles, or service-account keys, and binding cluster roles on
  EKS/AKS/GKE. Reads the actor, the grant's scope, and the grantee to tell
  routine access management apart from someone handing broad, lasting power to
  themselves or a party that shouldn't have it, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - iam
    - privilege-escalation
    - persistence
---

# Triage Steps

This class fires on access-management actions that are normal by themselves — grants, role bindings, key creation — done all day by IAM admins and infrastructure-as-code pipelines that exist to manage exactly this. The actor here is already authenticated and operating the account through its own APIs, so where it came from barely matters; the fact that a grant happened is not the signal. The signal is the shape of the grant: who made it, how much power it hands out, who receives it, and whether this actor has ever made a grant like this before. Triage here is reading that shape and deciding whether it looks like routine administration or someone minting lasting access for the wrong party — escalate or dismiss. This class turns on creating access — minting a credential, key, or grant — distinct from reading existing secrets and keys, which turns on the breadth of the reading; a read that immediately precedes a grant by the same actor is corroboration for the grant, not a reason to look past it.

Start from this detection's track record on this actor and account — a rule that fires whenever the IaC role provisions access and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a wildcard policy to a brand-new external grantee, a self-grant by a non-human actor) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Broad power handed out at once.** A wildcard or admin policy where a scoped one would do: `AttachUserPolicy` with `AdministratorAccess`, an `arn:aws:iam::aws:policy/*` attach, a `cluster-admin` ClusterRoleBinding, an Owner role binding at subscription scope. Real grants are usually narrow and named for a job; full power in one call is the tell, and the resource posture (Wiz high-privilege, admin-privilege) shows how much the grantee now reaches.
- **A grantee that doesn't fit.** The receiver is external, freshly created, a free-email domain, or a service account suddenly holding human-admin rights — `AddUserToGroup` putting a service identity into an admin group, a role binding to an identity outside the org. The identity directory (Graph/Okta users, role-assignments, service-principals) tells you whether the grantee exists in the org and what it already holds; power flowing to a party with no reason to hold it is off-pattern.
- **The wrong actor minting access.** A self-grant, or an action by a non-human actor that has no business creating IAM — an instance role calling `CreateUser`, a compute identity attaching policies to itself. Automation provisions to others on a pattern; it does not promote itself.
- **A new long-lived credential out of nowhere.** `CreateAccessKey`, `CreateLoginProfile`, a service-account key, or a new trust relationship appearing where the baseline shows none, or any of this landing outside a change window. A fresh standing credential where there has never been one is how a foothold is planted.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A confirmed IAM admin identity or a known infrastructure-as-code role making a grant it makes every day, inside a change window — even more so when the grantee is a service identity that already owns the resource.
- **It matches the baseline.** The same actor, grant scope, and grantee shape have appeared here before as normal provisioning.
- **The grant is scoped and named.** A narrow, job-specific policy or a binding at a tight scope, not a wildcard or account-wide admin role.
- **Broad rollout of a scoped grant.** The same scoped, named grant pattern lands across many accounts or namespaces on a known provisioning cadence — a named landing-zone or IaC provisioner doing what its documented pattern shows; a foothold targets one identity. Breadth alone does not rule out a wildcard or admin grant — an org-wide `AdministratorAccess` rollout still needs the actor and a change record to explain it, not just its wide shape.
- **Clean history.** Prior similar grants by this actor closed benign, with nothing new in the scope or grantee this time.

To confirm a lead instead of guessing, pull the thread: did the new credential or role get used right after it was created, or did the same actor make other control-plane changes in the same window? Corroboration turns a suspicious grant into a confirmed one.

# Output

## Decision
- **escalate:** a broad or permanent grant (wildcard, AdministratorAccess, cluster-admin), a grantee that is external/new/unexpected, a self-grant or a non-human actor minting IAM, or a new long-lived credential with no baseline — especially two together, or any one with the credential used right after.
- **dismiss:** a confirmed IAM admin or IaC role makes a scoped, named grant inside a change window and within baseline, with no broad scope, odd grantee, or new standing credential — the expected actor together with a documented pattern or change record, not the actor alone. A dismiss is a positive call that the grant is benign, made with that context in hand — an actor you confirmed, a pattern or change record you actually saw; an actor you couldn't resolve or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; a broad or admin grant, an unexpected grantee, or a new standing credential is not dismissed just because the actor is known — when the benign context is missing, the shape is off, or you're unsure, escalate.

## Evidence
The actor and whether it is a confirmed admin, automation, service, or new/unexpected identity; the scope and permanence of the grant; who the grantee is and whether they are normally privileged; whether a new credential was created; change-window and baseline fit; and prior dispositions of similar grants.

## Reasoning
Name the leads that decided it and how they stacked — an instance role granting itself AdministratorAccess outside any change window is escalate on its own; a known IaC role attaching a scoped policy to a service it owns, across the fleet, is dismiss.
