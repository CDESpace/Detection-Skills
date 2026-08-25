---
name: Cloud Cross Boundary Delegation Use
description: An identity crossing an account or project boundary by
  delegation - an assume-role chain deep enough to drop the original human,
  a signJwt loop onto itself, GetFederationToken turning a programmatic key
  into a browser session. Reads hop depth and whether this source ever
  served this destination.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - delegation
    - assume-role
    - impersonation
    - lateral-movement
    - privilege-escalation
  mitre:
    - T1199      # Trusted Relationship
    - T1134.001  # Token Impersonation/Theft
    - T1606      # Forge Web Credentials
    - T1538      # Cloud Service Dashboard
---

# Triage Steps

Delegation is how cloud accounts are built. Deploy pipelines assume a role in every environment account, platform services impersonate a per-tenant service account on every request, and vendors assume into your account to do the job you bought from them. So a role being assumed or a token being minted is not the signal. The signal is the shape of the trust path: how many hops it runs, whether the human at the head of it is still visible at the far end, and whether this source has ever served this destination before. The credential doing the hopping may be perfectly legitimate - the path is what decides.

Start from this detection's track record on this source and destination pair - a rule that fires on every deploy hop into the staging account and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (a self-impersonation loop, a long-lived key turned into a browser session) can carry the call. This class turns on the use of a delegation - the assume, the impersonation, the federation - distinct from the creation of the trust that makes it possible: a role trust policy widened to a new external account, or a workload-identity pool binding added, is cloud-iam-privilege-persistence's, which already treats a new trust relationship as its own escalate lead. Where the question is whose hands a credential is in - a new ASN or user-agent, a metadata token used off its instance, a first-ever write - that is cloud-stolen-credential-first-use's.

**Leads that point to a real threat** - what to look for in the data:

- **A chain deep enough to hide the human.** `AssumeRole` called from an already-assumed session, again, so that `userIdentity.sessionContext` at the far end no longer carries the original principal or its MFA fact, and the `RoleSessionName` is machine-generated noise rather than a name you recognize. Pipelines hop at a fixed depth with a session name that says which pipeline; a chain that grows an extra hop and loses the person is laundering, and the last session is the one holding the power.
- **A self-impersonation loop, or a token minted with a user-managed key.** `iam.serviceAccounts.signJwt` or `iam.serviceAccounts.generateAccessToken` where the caller and the target service account are the same identity, or an impersonation token minted using a user-managed service-account key instead of the platform's own metadata credential. The loop is how a principal holding only the signing permission turns it into full impersonation, and a user-managed key means someone is carrying that identity around in a file.
- **actAs attaching a more privileged identity to a workload.** `iam.serviceAccounts.actAs` used to attach a service account with broader roles onto a VM, a Cloud Run or Function deployment, or a job. The caller never gains the permissions itself - the workload it just created holds them, and every later call comes from the machine rather than the person.
- **A programmatic key turned into an interactive session.** `GetFederationToken` or `GetSigninToken` called by a long-lived IAM user or access key, producing a console session. Programmatic credentials have no use for a browser; that conversion is how a stolen key becomes a pair of hands clicking through the console, and it also breaks the MFA story the console would otherwise enforce.
- **A source and destination pair with no history, or a hop right after the trust widened.** The source identity has never assumed into this account or project before, or the destination role's trust policy was widened - a new external account principal, a wildcard subject on a workload-identity pool - shortly before the first assume against it. New trust plus immediate use, in one window, is the two halves of the same move.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The deploy role's hop by design.** The chain runs at its usual depth, the `RoleSessionName` carries the pipeline's own prefix, and the source address is the runner's own egress - with the same source and destination pair appearing on every deploy across the window. All three should line up; a familiar destination reached at an unfamiliar depth, or with a session name you cannot place, is not this lead.
- **A platform service impersonating per-tenant accounts at its steady cadence.** The caller is the platform's own service identity, the targets are the per-tenant service accounts it serves, and the calls arrive at an even machine rhythm with identical parameters across many targets rather than as one burst against one target. Many targets, constant shape, no human judgment between them is what per-request impersonation looks like.
- **A documented vendor integration.** The assume comes from the vendor's own account id, carries the agreed `ExternalId` on the call, and lands on the role provisioned for that vendor, with follow-on calls that stay inside the read-only set that integration does. The account id and `ExternalId` are in the audit row - a vendor you assume rather than see is not context.
- **Break-glass federation by a named engineer inside a window.** The federating identity resolves in the identity directory to a named person, an incident or change window covers the timestamp, and the console session's follow-on calls match that task instead of ranging into unrelated services. The session's own activity is the check that makes this lead hold.

To confirm a lead instead of guessing, pull the thread: what did the final session actually do after the hop, and has this source ever reached this destination in its own history?

# Output

## Decision
- **escalate:** a chain that adds a hop and drops the original human, a signJwt or generateAccessToken self-impersonation loop, an impersonation token minted with a user-managed key, actAs attaching a more privileged service account to a VM or job, a programmatic key converted into a console session, or a source-and-destination pair with no history - especially one assumed straight after that role's trust was widened.
- **dismiss:** the deploy role hopped at its usual depth with its own session-name prefix from the runner's egress, a platform service impersonated its per-tenant accounts at its steady cadence, a documented vendor assumed with the agreed ExternalId from its own account, or a named engineer federated inside an incident window and the session's calls match that task. A dismiss is a positive call that the delegation is benign, made with that context in hand - a chain depth and session name you matched, an ExternalId and vendor account you read, a window and follow-on calls you checked; a chain whose head you couldn't recover or a destination this source has never served is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the human at the head of the chain is gone, a key became a console session, or you're unsure, escalate.

## Evidence
The full hop sequence with the calling identity at each step, the hop depth against this pipeline's usual depth, the RoleSessionName and whether it carries a recognizable prefix, whether sessionContext still carries the original principal and its MFA fact, the source and destination account or project pair and their history together, the ExternalId and source account on a vendor assume, the caller-and-target pair on an impersonation call and whether a user-managed key was used, the source address against the runner's or workload's own egress, what the resulting session did next, and any trust-policy or workload-identity binding change on the destination earlier in the window.

## Reasoning
Name the leads that decided it and how they stacked - a service account calling generateAccessToken on itself with a user-managed key, then assuming into a production project it has never served, is escalate on its own, while the deploy role hopping into the staging account at its usual depth with its pipeline session-name prefix from the runner's egress is dismiss.
