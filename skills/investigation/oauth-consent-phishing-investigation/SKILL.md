---
name: oauth-consent-phishing-investigation
description: |-
  Investigate escalated alerts for suspicious OAuth application consent
  grants. Determines whether a newly consented application is a consent
  phishing (illicit grant) attack by examining app provenance, requested
  scopes, grant velocity across the tenant, and post-consent API activity.
  Produces a verdict and containment recommendations.
type: investigation
version: 1.0.1
metadata:
  author: vega-security
  labels:
    - oauth
    - m365
    - initial-access
---

# OAuth Consent Phishing Investigation

Consent phishing bypasses credential theft entirely: the victim authorizes a
malicious OAuth application, and the attacker operates through the granted
tokens. MFA does not help after the grant. This skill investigates an
escalated alert for a suspicious consent grant and produces a verdict.

## Scope of the investigation

The alert supplies: the consenting principal, the application (client ID,
display name, publisher, redirect URIs), the granted scopes, and the grant
timestamp.

## Steps

### 1. Application provenance

- Look up the client ID in the tenant's app registrations and in known-app
  reputation sources.
- Red flags: publisher domain registered recently, display name imitating a
  well-known product ("Docu5ign", "Adobe PDF Online"), redirect URI on a
  low-reputation or newly registered domain, verified-publisher status
  absent.

### 2. Scope risk

Classify the granted scopes:

- **High risk:** `Mail.Read`, `Mail.Send`, `MailboxSettings.ReadWrite`,
  `Files.ReadWrite.All`, `offline_access` combined with any of the above.
- **Moderate:** `User.Read.All`, `Contacts.Read`, `Calendars.Read`.
  `User.Read.All` is a full directory read of every user — it sits here
  because it enables tenant-wide reconnaissance rather than direct data
  theft; treat it as high risk when combined with `offline_access`.
- `offline_access` matters: it converts a one-time grant into durable
  refresh-token access.

### 3. Tenant-wide grant velocity

Query consent events for the same client ID across the tenant over the past
14 days. Multiple users consenting to a new app within a short window is the
strongest single indicator of an active phishing campaign.

### 4. Post-consent activity

Pull API/audit activity attributed to the app's service principal since the
grant: mail rules created, mass file downloads, mail sent on behalf of the
user, token refreshes from unfamiliar ASNs.

## Verdict rule

- **malicious** — provenance red flags plus high-risk scopes plus
  post-consent abuse or multi-user grant velocity.
- **suspicious** — provenance red flags with high-risk scopes but no
  observed abuse yet.
- **benign** — verified publisher, expected scopes, activity consistent with
  the app's stated purpose.
- **inconclusive** — audit data unavailable or grant too recent; recommend a
  re-check window.

## Output

### Verdict

`malicious` / `suspicious` / `inconclusive` / `benign`, per the rule above,
plus the provenance, scope, velocity, and post-consent findings behind it.

### Recommended actions

Scale to the verdict. For `malicious`:

1. Revoke the app's refresh and access tokens; disable the service principal.
2. Remove the enterprise application / domain-wide delegation.
3. Reset sessions for all consenting users; hunt for mail rules and
   exfiltration created post-grant.
4. Add the client ID and redirect domains to the tenant's app consent
   blocklist, and tighten the user-consent policy if it allowed the grant.

For `suspicious`: disable the service principal pending review, notify the
consenting users, and re-run the post-consent activity check after 24
hours before restoring access. For `inconclusive`: set an explicit re-check
window for the missing audit data, and treat any new grants for the same
client ID in the meantime as grounds to escalate to `suspicious`.

### Evidence

The app-registration and publisher lookup results, the classified scope
list, the tenant-wide consent-event query results, and the post-consent
API/audit activity attributed to the service principal.

### Reasoning

One line per step (provenance, scopes, velocity, post-consent activity)
stating what was found, then the verdict derivation from the rule above.
