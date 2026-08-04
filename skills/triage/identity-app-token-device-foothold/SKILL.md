---
name: Identity App Token Device Foothold
description: Triage an identity alert where a non-human app, token, or device
  gains standing in the directory — OAuth consent grants with risky scopes
  (consent phishing), a secret or credential added to back an integration,
  suspicious redirect URIs, and rogue or scripted device registration. Reads the
  directory audit trail and app/device inventory to tell a verified app or
  managed-device enrollment apart from consent phishing or a rogue registration
  that survives a password reset, and decides escalate or dismiss. Boundary —
  this skill owns the foothold mechanism — consent and the app permissions it
  grants, a secret for an integration, a redirect URI, a device enrollment; the
  directory role or privileged group an account is then assigned is a privilege
  grant, not a foothold.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - identity
    - oauth-consent
    - device-registration
    - persistence
---

# Triage Steps

This class fires when something non-human gains a hold in the directory — a user consents to an app, a secret is added to an integration, a redirect URI is set, a device enrolls. These are routine: people approve productivity apps, admins wire up vendor integrations, employees enroll new laptops, so the event itself is not the signal. The signal is whether the app or device is known and verified and whether the access it asks for fits a real need. These footholds are durable backdoors — they keep working after a password reset — so an attacker reaches for them, and they look like the legitimate version until you check the publisher, the inventory, and the scopes. Triage here is deciding: is this a verified app or a managed enrollment, or is it consent phishing or a rogue registration?

Begin with this detection's track record and the app/device inventory — a publisher-verified app already in the inventory, or a recurring enrollment pattern always closed benign, starts the call near dismiss — then read the audit trail for the leads below. None is required on its own; they stack, and a single strong one (an unverified app asking for broad mail access, an off-tenant redirect) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Unverified app, broad scopes.** Consent goes to an app that is unverified or registered minutes ago, asking for high-risk delegated or application scopes — `Mail.Read`, `Files.ReadWrite.All`, `Mail.Send`, `Directory.Read.All`, `Application.ReadWrite.All`. The unknown-publisher-plus-broad-access shape is the classic consent-phishing tell.
- **Redirect points off-tenant.** A redirect URI set to an attacker-controlled or off-tenant host — a domain that is not yours or a raw IP — so tokens flow somewhere you do not control. A **malicious or suspicious reputation verdict on the redirect host or domain** makes it decisive.
- **A device enrolled by the wrong client.** A device registration from a scripted client fingerprint or an unusual network, not matching any managed enrollment for the owning user — a rogue device joining to ride the user's access.
- **A secret feeds broad reads.** A secret or credential added to an integration whose app then reads widely across the directory — credential added, then a burst of Graph directory reads from that app in the same window.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **Verified and already in inventory.** The app is publisher-verified and already present in the app inventory (service-principals, applications, oauth2-permission-grants), and this consent is one more user approving an app the org already runs at scopes it already holds. A first-time high-risk application permission — `Application.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite` — granted to even a known app is a new standing grant, not a repeat approval, and still needs a rollout or change record behind it.
- **Admin-consent behind a rollout.** An admin-consent grant that follows a known deployment of that app to the org, applied broadly rather than to one user.
- **The device matches a managed enrollment.** The registration lines up with a managed-enrollment or known-device record for the owning user (managed-devices), from the expected enrollment client.
- **An established integration.** The secret, redirect, or permission belongs to a baseline integration that has been in place and unchanged.
- **A broad rollout, not one target.** The same consent or enrollment appears across many users on a known cadence — the shape of a sanctioned rollout, which moves broadly; a phishing grab hits one account.

To confirm a lead instead of guessing, pull the thread: after the consent or enrollment, did the app start reading mail or files, or did the new device sign in and pull data, in the same window? Corroboration turns a suspicious grant into a confirmed foothold.

# Output

## Decision
- **escalate:** consent to an unverified app with high-risk scopes, an off-tenant redirect URI or one with a malicious or suspicious verdict, a device registration that does not match managed enrollment, or a secret feeding broad directory reads — especially two together, or any one with the app or device using the access right after.
- **dismiss:** a verified, already-inventoried app at the scopes it already holds, an admin-consent rollout, a managed-device match, or an established integration explains it. A dismiss is a positive call that the consent or enrollment is benign, made with that context in hand — a publisher-verified app you found in the inventory, a managed-enrollment record you matched to the device; a publisher you couldn't verify or an enrollment you couldn't match is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or the app is unverified with broad scopes, or a first-time high-risk application permission lands on even a known app with no rollout behind it — escalate.

## Evidence
The app's publisher-verification and inventory status, the scopes requested, the redirect-URI host and its reputation, whether the device matches a managed-enrollment record, user- vs admin-consent, broad rollout vs single target, and prior dispositions for this rule.

## Reasoning
Name the leads that decided it and how they stacked — an unverified app granted `Mail.Read` with an off-tenant redirect, then reading mailboxes, is escalate on its own; a publisher-verified app already in inventory getting one more user's consent is dismiss.
