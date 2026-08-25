---
name: Cloud Stolen Credential First Use
description: A credential driven from a place or by a client it has never
  used - a long-lived key calling from an unfamiliar ASN, a workload role
  used from an address that is not the instance's own or its NAT egress, a
  first write by a reader. Reads how far the source and client sit from
  history.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - credential-provenance
    - access-key
    - workload-identity
    - initial-access
    - credential-access
  mitre:
    - T1078.004  # Cloud Accounts
    - T1552.005  # Cloud Instance Metadata API
---

# Triage Steps

Cloud credentials legitimately move around. People work from home, from a hotel, from a new VPN egress; runner pools get rebuilt on fresh addresses; a workload's calls arrive from a NAT gateway that is not the instance's own address. So a call from a new place is not the signal. The signal is whether the same actor is still behind the credential: do the source, the user-agent, and the call mix hold together as one person or one pipeline doing its usual job, or did all three change at once? On a provider-audit-only alert there is no sign-in series to lean on, so the caller's own history is the baseline you have.

Start from this detection's track record on this principal - a rule that fires whenever the runner pool rolls onto new addresses and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (a workload role used from an address that is not the workload's, a first-ever write from an ASN this key has never touched) can carry the call. This class turns on caller provenance - who is driving the credential and from where - on any call class, sweep or not. The shape and breadth of the reading on a sweep-shaped alert is cloud-recon-secret-harvest's; whether a sign-in granted access to someone other than the owner, read from the IdP sign-in stream, belongs to identity-authentication-abuse and application-account-auth-abuse; and the act of minting a delegated or console session as a trust-path hop is cloud-cross-boundary-delegation-use's, while the question here is simply whose hands the credential is in.

**Leads that point to a real threat** - what to look for in the data:

- **A long-lived key calling from an ASN, country, or user-agent it has never used.** A `sourceIPAddress` in an ASN absent from this key's own history, a country the principal has never called from, or a `userAgent` that switches character - `aws-cli/2` where every prior call carried an SDK string, or a bare Python or Go client on a key that only ever came through a console session. Read all three together: one changed is a trip, all three at once is a different operator on the same key.
- **A workload credential used away from its workload.** An instance, task, or pod role calling from a source address that is neither the workload's own address nor the egress its other calls come from - the off-instance metadata token, where a role credential lifted from the instance metadata service is replayed from somewhere else. This lead can carry the escalate alone: that credential has no business anywhere but the workload it was issued to.
- **An interactive session on a programmatic-only identity.** A console sign-in, or a console session, on an identity whose entire baseline is SDK and CLI calls, and without MFA behind it. The identity just gained a pair of hands it never had, and the account's usual guardrail on interactive access did not apply.
- **A first write from a reader, or a first call after dormancy.** A principal whose whole history is `Describe`, `List`, and `Get` making its first mutating call, or a key with no activity across the baseline suddenly working. Credentials that wake up after a long silence are the shape of a key that was found somewhere - a repository, a laptop, a paste - rather than one that was always in use.
- **Identity, ASN, and call mix shifting together in one short window.** Not one anomaly but three at once: a new source, a new client, and a set of calls this principal never makes, inside minutes. Any of the three alone has a boring explanation; arriving together they are one operator picking up a credential and trying it out.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The same human session continues across the change.** The actor's other calls that day come from the same new ASN too, the directory resolves the principal to an active named person, and the work before and after the address change is the same work - a home ISP or VPN egress the actor is simply sitting behind. The continuity is the check; a single call from a new place with nothing around it is not this lead.
- **A runner-pool rollout onto a documented CI egress range.** The new source falls in a documented CI/CD or runner egress range, and the call pattern is the pipeline's usual set, in its usual order, with its usual user-agent. The address changed and nothing else did, which is what a pool rebuild looks like.
- **The "new" address is the account's own egress.** The source resolves to the account's own NAT gateway, proxy, or provider egress for that same workload, which the account's own network resources confirm. A workload whose calls arrive from its NAT gateway rather than its instance address was never using an off-instance token.
- **Break-glass or on-call use that a ticket covers.** A named incident or change ticket covers the timestamp, the identity resolves in the directory to the engineer who was on call, and the calls match that task rather than ranging into unrelated services. The calls are what make this hold - a window without matching activity is not context.

To confirm a lead instead of guessing, pull the thread: do this principal's other calls in the window come from the same new source, and is that source the account's own egress or the workload's own address?

# Output

## Decision
- **escalate:** a workload role used from an address that is not the workload's own or its NAT egress, a long-lived key calling from an unfamiliar ASN, country, or user-agent, a console session without MFA on a programmatic-only identity, a first-ever write by a read-only principal or a first call after long dormancy, or source, client, and call mix shifting together in one window.
- **dismiss:** the same human session continues across the change with the directory naming an active person, a runner-pool rollout onto a documented CI egress range with the pipeline's usual call set, the new source resolves to the account's own NAT gateway or proxy for that workload, or a named ticket covers break-glass use and the calls match the task. A dismiss is a positive call that the caller is who the credential belongs to, made with that context in hand - a continuing session you traced across the window, a documented egress range or NAT gateway you confirmed, a ticket and matching calls you read; a source you couldn't attribute or a principal the directory couldn't place is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when a workload credential is used off its workload, several provenance facts shift together, or you're unsure, escalate.

## Evidence
The principal and its type from the identity directory, the credential kind - long-lived key, service-account key, workload role, console session - the source address and its ASN, country, and reputation against that principal's own history, the user-agent and how it compares with prior calls, whether a workload credential's source matches the workload's address or the account's NAT egress, whether MFA was present on an interactive session, the call mix in the window against the principal's baseline including its first write, the time since the credential's last activity, and any ticket or change window covering the timestamp.

## Reasoning
Name the leads that decided it and how they stacked - an instance role calling from a residential ASN nowhere near the account's egress, then making its first write, is escalate on its own, while a named engineer's key showing a new home ISP that every one of her other calls that day also came from is dismiss.
