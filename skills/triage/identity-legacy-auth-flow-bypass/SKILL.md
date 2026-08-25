---
name: Identity Legacy Auth Flow Bypass
description: A sign-in that travelled a flow skipping MFA and conditional
  access - a device-code or ROPC token for a browser-only user, basic auth
  on IMAP or ActiveSync with no factor recorded, first-time CLI auth. Reads
  which protocol carried it and whether any factor was taken, against the
  account's history.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - device-code-flow
    - ropc
    - basic-auth-protocols
    - stealth
    - initial-access
  mitre:
    - T1078.004  # Cloud Accounts
    - T1550.001  # Application Access Token
---

# Triage Steps

Every estate still carries flows that predate its controls. Device code exists so a TV or a headless box can sign in, ROPC exists for old clients that only know a username and a password, IMAP and SMTP AUTH keep a printer relaying mail, and none of them can carry a modern MFA prompt or a device check. So an account using one of these paths is not the signal by itself. The signal is whether an identified legacy client genuinely needs that path, or whether a human account with a normal browser life suddenly travelled the one route where conditional access has nothing to say.

Start from this detection's track record on this account and this client - a mail appliance that has authenticated over the same protocol from the same internal address every day for months, always closed benign, starts the call near dismiss - then read the sign-in for the leads below. None is required on its own; they stack, and one strong lead (a device-code or ROPC token for an account whose entire history is interactive browser sign-in) can carry the call. This class turns on the path the sign-in travelled and what that path skipped, distinct from the burst shape and the device or geography of the sign-in, which stay with the authentication-abuse skill, and distinct from the configuration change that re-opened legacy auth, which is the control-tampering skill's. A machine credential judged on whether its holder is still the workload it belongs to is cloud-stolen-credential-first-use's; here the subject is a human account on a non-human path.

**Leads that point to a real threat** - what to look for in the data:

- **Device code or ROPC for a browser-only human.** A device-code or resource-owner-password-credentials token issued to a person whose 3-day history is interactive browser sign-in, or a device-code flow through a broker client. Device code was built for a screen with no keyboard; when a normal office account uses it, someone read a code to them, and ROPC hands the password straight to a client that never prompts for a factor.
- **A basic-auth protocol success with no factor recorded.** `auth_protocol` naming IMAP4, POP3, SMTP AUTH, EWS or ActiveSync, with `has_mfa` false and `auth_factors` empty, on an account that otherwise signs in through the browser with a factor every time. Mail protocols are the oldest MFA-free door in the estate, and a success there is worth more than a hundred failures.
- **Single factor where conditional access normally forces more.** A success recorded as single-factor for a user, application or location where the policy normally requires a strong factor - the same account satisfying a factor on every other sign-in in the window, and not on this one. The gap between the policy and this one event is the finding.
- **The client id claims one thing and the request says another.** A first-party client id presented while the user agent, the nonce or the binding disagrees - a first-party Office or portal client id arriving with a bare SDK, `curl` or `python-requests` user agent that client could never send, a missing-nonce error on a client that always sends one, or a `binding_method` that does not match the client the account is registered to use. The claim is cheap; the fingerprint around it is not.
- **Scripted or non-interactive authentication for a person who never uses one.** `logon_is_interactive` false, or an `initiation_type` showing a scripted or CLI client, on an account with no history of command-line or SDK sign-in. An engineer's shell habit shows up every day; a first one on the day the alert fired does not.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **An identified legacy client doing exactly this every day.** The same client id and user agent, from a fixed internal IP, on the same protocol, at the same hours across the whole window - a multifunction printer relaying SMTP, a mail-enabled appliance, an old EWS integration. The rule-out is the sameness across days plus the source being an internal address you can point at, not the mere fact that the client looks old.
- **A documented migration or cutover window.** A mail migration or SSO cutover is on record and its window contains this sign-in, and the protocol and the source match what that project runs. The window explains a burst of IMAP or EWS auth that would read badly on any other day.
- **Real device-code onboarding.** The same user, the same `autonomous_system`, minutes apart from an interactive sign-in, and a managed device appearing on that account right after - `is_managed` true. That sequence is a person enrolling a new device, and it is the one benign shape device code has.
- **An engineer whose baseline is daily CLI or SDK auth.** The same client id, the same network, non-interactive sign-ins on most days in the window, on an account the directory shows as engineering. The path is that person's normal way of working, and the history proves it rather than the job title.

To confirm a lead instead of guessing, pull the thread: did MFA get satisfied anywhere in this session, and does this account have interactive sign-ins from the same ASN before or after - or is this flow the only way it ever authenticates? Corroboration separates a legacy client on its daily route from an actor choosing the unwatched one.

# Output

## Decision
- **escalate:** a device-code or ROPC token for a human account whose history is browser sign-in, a basic-auth protocol success with no factor recorded, a single-factor success where the policy normally forces a strong factor, a client id whose user agent, nonce or binding disagrees with it, or scripted and non-interactive authentication for a person who has never used one.
- **dismiss:** an identified legacy client on a fixed internal IP repeating this exact sign-in daily, a documented migration or cutover window containing it, a device-code enrollment followed by a managed device on that account, or an engineer whose baseline is this same client and network. A dismiss is a positive call that the flow is benign, made with that context in hand - a client and source you matched across days, a migration window you found on record, an enrollment you saw complete; a client you couldn't identify or a history you couldn't pull is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when a human account travelled a factor-free path with no legacy client behind it, or you're unsure, escalate.

## Evidence
The `auth_protocol` and flow used, `logon_is_interactive` and `initiation_type`, `has_mfa`, `auth_factors` and `factor_type` on the sign-in, the client id and its user agent, nonce or `binding_method` fit, the source address and whether it is a fixed internal one, the account's own 3-day sign-in history and whether it ever uses this path, what the directory says the account is (person or workload, engineering or not), any managed device appearing right after, and any migration or cutover window on record.

## Reasoning
Name the leads that decided it and how they stacked - a device-code token for a finance user whose whole history is browser sign-in, with no interactive sign-in from that ASN and no device enrolled afterwards, is escalate on its own; the same SMTP AUTH from the same print server at the same hours all 3 days is dismiss.
