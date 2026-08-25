---
name: Identity Preauth Account Probing
description: A burst of failed lookups at the sign-in edge asking which
  accounts exist - dozens of distinct names from one hosting source, none
  ever provisioned, names built on the org's naming convention, then a
  password attempt on the one that resolved. Counts distinct names per
  source and why each failed.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - username-enumeration
    - user-not-found
    - realm-discovery
    - reconnaissance
    - discovery
  mitre:
    - T1589.002  # Email Addresses
    - T1087.004  # Cloud Account
    - T1110.003  # Password Spraying
---

# Triage Steps

The sign-in edge fails all the time for boring reasons. A client keeps a wrong saved address, a directory sync still asks for people who left, autodiscover chases a mailbox that moved, a monitor pings the login page every minute. So a pile of failed lookups is not the signal. The signal is the shape of the names being asked for: many distinct usernames from one source, all of them coming back as accounts that do not exist, is someone building a list of the ones that do - the step before any password is ever tried.

Start from the source, because before authentication there is no actor identity to baseline - only where the requests came from. A fixed internal address that has produced the same failures every day starts the call near dismiss; an external ASN with no history in this tenant does not. Then read the leads below. None is required on its own; they stack, and one strong lead (dozens of distinct never-provisioned names from one hosting ASN, all user-not-found) can carry the call. This class turns on the probe that happens before authentication, distinct from authenticated directory reading by an actor already inside, which is the directory-reconnaissance skill's, and distinct from password attempts against accounts that do exist, which stay with the authentication-abuse skill. One trap worth naming: a validity sweep never tries a password, so "no success followed the failures" is trivially true here and rules nothing out.

**Leads that point to a real threat** - what to look for in the data:

- **Many names, one source, all of them user-not-found.** Count distinct usernames per source and read `status_code` with `status_detail`: the account does not exist, rather than the password was wrong or the factor failed. A password attack repeats a handful of real names; a validity sweep touches each name once and never comes back to it.
- **The probed names follow your naming convention but were never provisioned.** first.last, flast, firstl or firstname.l patterns that match exactly how your directory builds addresses, on people who have never had an account here. That is a generated or scraped list being tested against your convention, not a stale record of anyone real.
- **Realm or tenant discovery from outside, then one password attempt.** Tenant, realm or federation lookups from an external ASN, followed inside the same window by the first password attempt on the single name that resolved. The pivot from "does this exist" to "let me in" is the whole point of the probe, and seeing both halves is decisive.
- **The source has no history here.** A hosting, VPS or anonymizer ASN, `is_proxy_or_vpn` true, or an `isp` and `autonomous_system` with no successful sign-in for this tenant anywhere in the window. Legitimate broken clients and syncs come from places that also succeed; a probe source only ever fails.
- **The name that resolved is the name that gets attacked.** Minutes after one probed username stops returning user-not-found, that same account starts collecting real authentication attempts. The list-building worked, and the follow-up is already in the data.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **One broken client, one username.** Hundreds of events but one or two distinct usernames, from a fixed internal IP, retrying on a steady timer - a client holding a wrong saved identifier. The volume sits in the events, not in the names, and the distinct-name count is what separates this from a sweep.
- **A stale directory sync.** The probed names match people deprovisioned in the last cycle, and the source is the SCIM or HR-sync integration's own address, on its usual cadence. The sync is asking for accounts it still remembers, which is the mirror image of a probe - real former people rather than invented names.
- **Autodiscover or a synthetic monitor.** Mail autodiscover requests for former addresses of mailboxes that still exist, or a login-page monitor hitting the same non-existent test identity at a fixed interval from a known monitoring source. Both are recognizable by their exact repetition and their single target.
- **Partner realm lookups the trust already lists.** The probed realm or domain belongs to a federated partner or tenant that the trust configuration already names, and the lookups arrive from that partner's own ASN in their normal pattern. The lookup is how federation works, and the configuration is the proof.

To confirm a lead instead of guessing, pull the thread: did any probed name come back as bad-password or a success rather than user-not-found, and does that source ASN have any successful sign-in history in this tenant? Corroboration separates a sync asking for the departed from an outsider mapping the living.

# Output

## Decision
- **escalate:** many distinct usernames from one source all returning user-not-found, probed names matching your naming convention but never provisioned, realm or tenant discovery from an external ASN followed by a password attempt on the name that resolved, a source ASN with no history in this tenant or flagged as proxy or hosting, or a resolved name that starts collecting authentication attempts minutes later.
- **dismiss:** one or two distinct usernames behind a large event count from a fixed internal client, a stale SCIM or HR sync asking for recently deprovisioned people, autodiscover or a synthetic monitor on its cadence, or partner realm lookups the trust configuration already lists. A dismiss is a positive call that the failures are benign, made with that context in hand - a distinct-name count you measured, a source you matched to a sync, monitor or partner, names you matched to real former employees; a source you couldn't attribute or a name set you couldn't place is not that context, and absence of a bad sign is not proof it's good. Note that no success after the failures is not evidence here, since a probe never tries a password. Dismiss is logged and reopenable; when the names are many and never existed, or you're unsure, escalate.

## Evidence
The distinct-username count and the event count per source, `status_code` and `status_detail` showing user-not-found versus bad-password, whether the probed names match the org's naming convention and whether any of them ever existed, the source address and its `autonomous_system`, `isp` and `is_proxy_or_vpn`, whether that source has any successful sign-in history in the window, any first password attempt on a name that resolved, and any sync, monitor or federation configuration that claims the source.

## Reasoning
Name the leads that decided it and how they stacked - 180 distinct first.last names from one hosting ASN, every one user-not-found, then a password attempt on the single name that resolved, is escalate on its own; 900 failures for one saved wrong address from a fixed internal print server is dismiss.
