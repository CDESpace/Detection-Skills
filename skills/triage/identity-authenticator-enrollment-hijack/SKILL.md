---
name: Identity Authenticator Enrollment Hijack
description: A new authentication factor or temporary access pass landing on
  a person's account - a method registered minutes after a password reset, a
  pass redeemed from a new country with no help-desk request, SMS added
  where only a passkey stood. Reads who registered it, from what device and
  where.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - mfa-enrollment
    - temporary-access-pass
    - factor-downgrade
    - persistence
    - credential-access
  mitre:
    - T1556.006  # Multi-Factor Authentication
    - T1078.004  # Cloud Accounts
---

# Triage Steps

Factors get registered all day for good reasons. People replace phones, laptops get rebuilt, new hires enroll on day one, help desks issue temporary passes to someone locked out, and whole fleets move to passkeys on a project plan. So a new authentication method appearing on an account is not the signal - and it reads as the account getting stronger, which is exactly why this class slips through. The signal is whether the person who registered it is the account owner acting from a context they already hold, or someone who just took the account and is now installing their own way back in, one that survives the password reset that follows.

Start from this detection's track record on this account and this method type - a rollout that registers the same factor for hundreds of users on managed devices, closed benign every time, starts the call near dismiss - then read the session that did the registering for the leads below. None is required on its own; they stack, and one strong lead (a factor registered minutes after a password reset from an ASN the account has never used) can carry the call. This class turns on the factor now on a human account and who put it there, distinct from the direction of a configuration change, which is the control-tampering skill's, and distinct from a non-human app, secret or device gaining standing, which is the app-token-device-foothold skill's. A registration reads as tightening on its face, so judge the session behind it rather than the direction of the change.

**Leads that point to a real threat** - what to look for in the data:

- **The factor lands right behind a reset or a risky sign-in.** A method registered minutes after a password reset, a risk detection, or a sign-in from an `autonomous_system` and `country` the account has never used. That ordering is the whole adversary-in-the-middle follow-up in one line: the session that stole the account registers the factor that outlives the cleanup. Read the timestamps closely - minutes matter here, hours are a different story.
- **A temporary access pass with nothing behind it.** An admin-issued temporary access pass created with no help-desk request or ticket on record, redeemed from a new country or ASN, sometimes issued by an admin who does not normally support that user or that department. A pass is a bypass of every other factor for its lifetime, so who asked for it is the question.
- **One actor, several accounts.** The same registering principal adding methods to several accounts inside one window. A person refreshes their own device; an actor working through a list registers on other people's accounts, and the count of distinct target accounts per registering principal is the measurement.
- **A phishable method added, or the strong one removed.** SMS, voice call or secondary email added to an account whose `auth_factors` were passkey or authenticator-app only, or the existing strong `factor_type` deleted or reset right after the new one is written. Either way the account ends the window weaker than it started, which is the opposite of what a real device refresh does.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The owner's own device refresh.** The registering principal is the account owner, the session is interactive, `is_managed` and `is_compliant` are true, and `autonomous_system` and `country` match the owner's baseline for the window. Often the old factor is removed by that same session, which is what replacing a phone looks like from the log side.
- **Onboarding or a help-desk recovery with a matching window.** The account was created hours earlier and had no prior factors, so the first registration is the enrollment itself; or a recovery flow is on record and its request and the registration line up in time and in the person handling it.
- **A fleet-wide rollout.** Many users, the same `factor_type`, the same window, each registration from that user's own managed device. A rollout moves broadly on a plan; a hijack takes one account, so measure the distinct-user count before reading anything into a single event.
- **Self-service reset with the existing strong factor satisfied.** The same session shows the owner satisfying the existing strong factor before the new method was written - a Yubikey or authenticator challenge passed, an Okta `binding_method` and `dthash` matching the owner's known device and `behaviors` showing nothing new. The registration is gated by something the owner alone holds.

To confirm a lead instead of guessing, pull the thread: what did the session that registered the factor authenticate with first, and did that same account or that same ASN do anything else in the window - another reset, a factor deletion, a sign-in to a new application? Corroboration separates a phone upgrade from a foothold.

# Output

## Decision
- **escalate:** a factor registered minutes after a password reset or a risky sign-in, especially from an unfamiliar ASN or country; a temporary access pass with no request behind it or redeemed from new infrastructure; one principal registering methods across several accounts; a phishable method added to a passkey-only account; or the strong factor deleted right after the new one lands.
- **dismiss:** the owner registered it from a managed, compliant device on their baseline network, onboarding or a recorded help-desk recovery explains it, a fleet-wide rollout covers it, or the existing strong factor was satisfied on that same session. A dismiss is a positive call that the enrollment is benign, made with that context in hand - a registering principal you matched to the owner, a device posture and baseline you actually saw, a rollout you counted across users; a session you couldn't place or a recovery request you couldn't find is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the registration follows a reset or a risky sign-in, when one principal touches several accounts, or you're unsure, escalate.

## Evidence
The registering principal and whether it is the account owner, an admin or a third party; the `factor_type` and `binding_method` added and whether it is phishable; `has_mfa` and `auth_factors` before and after, including any factor deleted in the same window; `is_managed` and `is_compliant` on the registering session; its `autonomous_system` and `country` against the owner's baseline; the time gap to any preceding password reset, risk detection or recovery request; the distinct-account count per registering principal; and prior dispositions for this rule on this account.

## Reasoning
Name the leads that decided it and how they stacked - an SMS factor registered 3 minutes after a password reset from an ASN with no prior sign-ins, on an account that held only a passkey, is escalate on its own; the same user registering a new authenticator from her managed, compliant laptop on her usual network while removing the old one is dismiss.
