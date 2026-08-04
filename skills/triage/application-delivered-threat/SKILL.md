---
name: Application Delivered Threat
description: Triage a mail or collaboration alert about a phishing, malware, or
  lure message reaching a person — known campaigns, malware or macro or
  scripting attachments delivered through defenses, sender impersonation, and
  internal-sender phishing. Reads whether the threat actually landed on a
  person, whether it got through or around defenses, and the sender's
  relationship and compromise status to tell sanctioned simulations and
  clean-verdict messages apart from a live threat, and decides escalate or
  dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - phishing
    - malware-delivery
    - initial-access
---

# Triage Steps

This class fires on messages shaped like a threat aimed at a person — a known campaign, a weaponized attachment, an impersonated or internal sender. The fact that a message looked malicious is not the signal; simulations, clean detonations, and routine campaign noise fire the same rules. The signal is whether a real threat reached a person and who sent it: a message a user acted on, a payload that arrived in an inbox, a confirmed-bad payload from a compromised internal or trusted-vendor mailbox — the visible edge of a live campaign. Triage here is reading delivery, the payload, and the sender, and deciding whether this is a simulation or clean-verdict message or a live threat pointed at a person. This class owns the delivered message and the user's action on it — the mail or collaboration delivery — distinct from any tenant-side consent or integration change that may follow, which is judged on the change itself.

Begin with this detection's track record on this recipient and sender — a rule that fires on a known sanctioned phishing-simulation domain and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a user click-through, a confirmed-bad payload from a compromised trusted sender) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **A human acted on it.** A user clicking through a protective link, or a message that arrived in an inbox: a `ClickedThrough` or `SafeLinks` click-through event, a `Deliver` event on the message. Delivery plus action is the strongest escalator here — unless the message is verified as a sanctioned simulation, where a click is the expected training outcome, not this escalator.
- **It got through or around defenses.** Delivery despite a malicious verdict, or delivery without passing email authentication: a message let through with `SPF`/`DKIM`/`DMARC` fail, an attachment delivered past the gateway. The control gap is real and that escalates even if no one clicked yet.
- **A confirmed-bad payload from a compromised trusted sender.** A confirmed-malicious attachment from a compromised internal or trusted-vendor mailbox escalates — full stop. Internal-sender phishing carries the same weight; it implies an already-compromised mailbox. A malicious or suspicious reputation verdict on the sender domain sharpens the call.
- **A weaponized attachment aimed at a high-value recipient.** A macro-enabled or scripting payload — a `.docm`, an `.html` smuggling file, a `.lnk` or script attachment — sent to finance or executives; the identity directory (Graph/Okta users, directory-roles) confirms the recipient's standing. A malicious or suspicious verdict on the attachment hash or an embedded URL adds weight.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A sanctioned simulation.** A phishing-simulation sender positively identified by a documented simulation domain or a known simulation header — a user click on such a verified simulation is the expected exercise outcome and stays dismissed. A message that merely reads like a simulation, without that documented domain or header, is not dismissable on that basis.
- **A clean detonation verdict.** A sandbox or detonation result that came back clean, with no user action.
- **A known, uncompromised sender from its normal source.** A trusted vendor or internal sender whose authentication passed, whose domain's reputation is known or clean, and whose mailbox shows no sign of compromise — but absence of clicks alone is not a dismiss reason.
- **Clean history.** This rule has closed benign on this sender or campaign before, with nothing new this time.

To confirm a lead instead of guessing, pull the thread: after delivery, did the recipient open the attachment, did the sender's mailbox send the same payload to others, or did a host event follow in the same window? Corroboration turns a suspicious message into a confirmed live threat.

# Output

## Decision
- **escalate:** a user click-through on a message not verified as a sanctioned simulation, delivery through or around defenses, a confirmed-malicious payload from a compromised internal or trusted-vendor sender, or a weaponized attachment aimed at a high-value recipient — a real malicious message that reached a person is escalate by default.
- **dismiss:** a verified sanctioned simulation — dismissable even when a user clicked — a clean detonation with no user action, or a known uncompromised sender whose authentication passed, with nothing unusual about the recipient. A dismiss is a positive call that the message is benign, made with that context in hand — a simulation domain or header you verified, a detonation verdict you actually saw come back clean; a simulation you couldn't verify or a sender whose compromise status you couldn't confirm is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or the message landed or came from a compromised sender — escalate.

## Evidence
Whether the message reached an inbox and whether a user acted, whether email authentication passed, the sender's relationship and compromise status, the reputation verdicts on the sender domain, attachment hash, and embedded URLs, the attachment or lure class and recipient role, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — a confirmed-malicious attachment from a compromised vendor mailbox is escalate on its own; a message from a sanctioned simulation domain with a clean detonation and no click is dismiss.
