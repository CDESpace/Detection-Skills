---
name: Identity Authentication-Artifact Pivot
description: A Kerberos or NTLM artifact presented to reach a host - a
  service ticket used with no request behind it, RC4 forced on a service
  whose baseline is AES, one source walking an account to many hosts, a
  machine or built-in administrator off its lane. Reads the request-and-use
  trail and logon type.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - kerberos-ticket
    - ntlm-hash
    - certificate-logon
    - lateral-movement
    - credential-access
  mitre:
    - T1550.003  # Pass the Ticket
    - T1550.002  # Pass the Hash
    - T1558      # Steal or Forge Kerberos Tickets
    - T1649      # Steal or Forge Authentication Certificates
    - T1212      # Exploitation for Credential Access
    - T1078.001  # Default Accounts
    - T1078.002  # Domain Accounts
    - T1078.003  # Local Accounts
---

# Triage Steps

Windows authenticates constantly, and it does it with the same artifacts an attacker wants: Kerberos tickets and NTLM handshakes are the plumbing behind every file share, every management console, every scheduled job, and legacy corners of the estate still negotiate the weak versions on purpose. So a ticket being issued or a hash-based network logon happening is not the signal. The signal is the fit between artifact, holder and path: whether the principal presenting it is the one it was issued to, from the host that legitimately holds it, along a path this account actually walks.

Start from this detection's track record on this account and source host - an SPN whose daily baseline is RC4 and a scanner account that authenticates to the same host list every night both start the call near dismiss - then read the authentication trail for the leads below. None is required on its own; they stack, and one strong lead (a service ticket used with no request behind it, or a built-in administrator account authenticating over the network to hosts it never touches) can carry the call. This class turns on the artifact as the authentication log shows it, where there is no process telemetry to lean on, so the account's own history and the target's own baseline are the whole measuring stick. The host-side act of forcing or capturing that authentication belongs to the coerced-authentication-relay skill, and stealing the ticket material off a host belongs to the credential-theft skill; when one of those co-fires, this skill still owns the call on the logon itself.

**Leads that point to a real threat** - what to look for in the data:

- **A ticket used where it was never requested.** A `4769` service-ticket event for an SPN with no matching `4768` from that source in the window, a service this account has no history with, or a ticket lifetime that does not match what this account normally gets. Forged and injected tickets show up as use without the request trail behind them, and `4771` pre-authentication failures with unusual failure codes around the same account are the same story from the other side.
- **Encryption downgraded against the SPN's own baseline.** A `4769` carrying RC4 for a service whose daily baseline is AES, requested by a client that normally negotiates AES. Compare the SPN against itself over the 3 days, not against a global idea of what is modern - the downgrade only means something when that service usually does better.
- **One source presenting one account to many hosts, or hash-only material where interactive belongs.** The same account authenticating from a single source to many destinations within minutes, or a `4624` network logon with logon type 9 and the `seclogo` process and `Negotiate` package, or a `4776` credential validation on hosts where only an interactive logon makes sense. Count the distinct destinations rather than reading rows.
- **An account authenticating outside its lane.** A machine account, a service account, a local account or the built-in administrator reaching over the network to hosts it never touches. The identity directory and the asset inventory tell you which lane the account has; a machine account authenticating to a workstation it has no relationship with is the classic pass-the-hash shape.
- **No strong mapping, or ticket tooling landing nearby.** A certificate-based logon that the KDC records as weakly mapped (events 39 and 41 on the domain controller), a logon arriving right after coerced authentication elsewhere in the estate, or ticket-manipulation tooling - a Rubeus or KrbRelayUp process or script block - seen on some other host inside the same window. Two independent sources pointing at the same account in the same minutes is what turns suspicion into a call.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **Legacy by design.** RC4 is this SPN's daily baseline across the whole window and nothing about it changed today, or NTLM because the target has no SPN registered or was reached by IP address rather than name, or an appliance or application that only supports RC4 or NTLM and always authenticates this way from the same source host. The rule-out is the sameness over days, not the presence of legacy alone.
- **A service account on its lane.** A scanner, patch, backup, monitoring or imaging account authenticating to the same wide host list, from its one known source, on its usual schedule - the same list, the same source and the same hours in the 3-day window. Width is that account's job; a change in the source or the host set is not.
- **One IP fronting many users by design.** A jump host, an RDS or Citrix session broker, a VPN concentrator or a NAT egress address, named as such in the asset inventory, with the same many-users-behind-one-source shape every day in the window.
- **Configuration or a declared engagement explains the artifact.** Constrained delegation is configured for that service account and the same S4U pattern recurs daily from the same source, so the account presenting another user's identity is the design. Or the tooling run falls inside a declared red-team or pentest window, on a security team member's own host per the inventory, with the account pairs in the logs matching that engagement - all three, not just the claim that testing is happening.

To confirm a lead instead of guessing, pull the thread: does a matching ticket request exist from that source host, and did the same account go on to authenticate to further hosts in the same window? Corroboration separates a legacy client doing its daily job from an artifact being replayed.

# Output

## Decision
- **escalate:** a ticket used with no matching request or for a service the account has no history with, an encryption downgrade against the SPN's own baseline, one source presenting an account to many hosts in minutes, hash-only network logons where interactive belongs, a machine, local or built-in administrator account authenticating outside its lane, a weakly mapped certificate logon, or ticket-manipulation tooling anywhere in the same window.
- **dismiss:** the legacy path is this SPN's or this appliance's unchanged daily baseline, a service account is on its known lane from its known source, an inventoried jump host or broker explains one source fronting many users, or configured delegation explains the artifact. A dismiss is a positive call that the authentication is benign, made with that context in hand - a baseline you compared the SPN against itself, a lane and a source you confirmed in the directory and the inventory; an account you couldn't place or a source host you couldn't resolve is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the artifact has no request behind it, the account is outside its lane, or you're unsure, escalate.

## Evidence
The artifact and how it was presented (ticket request and use, logon type and authentication package, credential validation, certificate mapping), the account and what kind it is per the identity directory (person, service, machine, local, built-in), the source host and the destination and their roles per the asset inventory, the SPN's own encryption baseline across the window, the account's own history with that service and that path, the distinct-destination count, and any related tooling or coerced authentication in the same window.

## Reasoning
Name the leads that decided it and how they stacked - a service ticket used against a file server with no matching request from the source and the same account reaching 14 hosts in 6 minutes is escalate on its own; an RC4 ticket for an SPN whose whole 3-day baseline is RC4, from the same appliance that authenticates that way every day, is dismiss.
