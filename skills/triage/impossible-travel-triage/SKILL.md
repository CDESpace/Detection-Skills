---
name: impossible-travel-triage
description: |-
  Triage impossible-travel sign-in detections by correlating the two sign-in
  events against VPN egress ranges, registered device identity, and MFA
  outcome. Escalates only when the geographic velocity cannot be explained by
  corporate VPN, mobile carrier NAT, or a previously registered device.
type: triage
version: 1.2.0
metadata:
  author: vega-security
  labels:
    - identity
    - okta
    - entra-id
    - cloud
---

# Impossible Travel Triage

Impossible-travel detections fire when a principal authenticates from two
locations whose distance implies a physical travel speed above a threshold
(commonly 800 km/h). The signal is cheap to compute and expensive to work:
the overwhelming majority of hits are VPN egress changes, carrier-grade NAT,
or GeoIP database drift.

## Inputs

You are given the triggering event pair: two sign-in events for the same
principal with timestamps, source IPs, resolved geolocations, device
identifiers, and MFA context.

## Decision procedure

Work through these gates in order. Stop at the first gate that resolves.

### 1. Known egress infrastructure

Resolve both source IPs against the organization's known egress inventory:

- Corporate VPN concentrator and SASE/SWG egress ranges
- Cloud provider ranges used by managed endpoints (e.g. Cloudflare WARP)

If **either** IP belongs to known egress and the other is consistent with the
user's recent baseline location, **dismiss** — record `vpn-egress` as the
dismissal reason. Known egress explains geography only: if the VPN/egress
session itself cannot be attributed to the user's registered device, do not
dismiss on this gate.

### 2. Device continuity

Compare device identifiers across both events: device ID, the IdP's device
context (Entra `deviceDetail`, Okta device context), and user-agent family.
A TLS client fingerprint is a valid comparator only where a network sensor
provides it — neither IdP exposes one in sign-in logs.

- Same registered, compliant device on both events → **dismiss**
  (`device-continuity`). GeoIP moved; the device did not. This also covers
  mobile carrier NAT: a leg originating from a mobile-carrier ASN with the
  same registered device is the user's own phone, not travel.
- A *different* but registered, compliant device on the distant leg (the
  user's laptop in the office, their phone on a carrier IP) → continue;
  the MFA-outcome gate decides.
- Unregistered or newly enrolled device on the *distant* leg → continue.

### 3. MFA outcome and factor type

- Distant leg completed phishing-resistant MFA (FIDO2/WebAuthn, device-bound
  passkey) → **dismiss** (`strong-mfa`).
- Distant leg used SMS/voice OTP, or MFA was satisfied by a *remembered
  session* → continue to escalation.

### 4. Escalate

Anything reaching this gate escalates: an unregistered device on the distant
leg without phishing-resistant MFA, session-token reuse from a new ASN on
either leg, or any pair no earlier gate resolved. Attach: both events,
egress-inventory misses, device comparison, and the MFA factor summary.

## Output

### Decision

`escalate` or `dismiss`, plus the reason code from the gate that resolved
(`vpn-egress` / `device-continuity` / `strong-mfa`). Never dismiss on GeoIP
distance alone.

### Evidence

Both sign-in events, the egress-inventory lookups, the device comparison,
and the MFA factor summary.

### Reasoning

Which gate resolved the pair and the specific facts that satisfied it; for
an escalation, why each earlier gate declined to dismiss.
