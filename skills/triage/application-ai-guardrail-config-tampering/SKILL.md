---
name: Application AI Guardrail Config Tampering
description: Triage an alert where an AI system's guardrails, permissions, or
  credential path are weakened through its configuration, agent settings
  granting wildcard or blanket tool permissions, disabling approval or
  confirmation prompts, redirecting the credential or API-key helper to an
  external script, downgrading model safety or guardrail settings, or widening
  an agent's tool or domain allowlist. Reads the actor, the direction of the
  change, and whether it is routine config management, to tell sanctioned
  administration apart from someone removing the brakes on an AI system, and
  decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - defense-evasion
    - policy-tampering
---

# Triage Steps

This class fires on configuration changes to an AI system that are normal admin work by themselves, editing an agent's settings, adjusting a permission, updating a guardrail. Teams tune these every week, so the fact that a config changed is not the signal. The signal is the direction and the actor: a change that removes a safety, a blanket tool permission, approval prompts turned off, a credential helper pointed at an arbitrary script, a model guardrail loosened, made by someone who does not own that configuration. An attacker who reaches an AI system's config weakens it so later actions run unseen and unchecked. Triage here is reading who made the change and whether it opens the system up. This class owns the configuration change itself; an untrusted instruction file that carries execution content is judged by Application AI Prompt Injection, and adding a whole new tool is judged by Application AI Tooling Supply Chain.

Begin with this detection's track record on this actor and system, a rule that fires when the platform team tunes agent settings and is always closed benign starts the call near dismiss, then read the leads below. None is required on its own; they stack, and a single strong one (approval prompts disabled by an unexpected actor) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **A blanket permission granted.** Agent settings widened to a wildcard or unrestricted tool grant, a Claude Code `settings.json` permission such as `Bash(*)` or a bare `"*"`, or an equivalent allow-all in a Cursor or agent config, handing the agent unconstrained capability.
- **Approvals or confirmations turned off.** A change that removes the human check before an agent acts, a default mode set to bypass permissions, auto-approve or "always allow" enabled, an interactive confirmation disabled, so subsequent actions run without a prompt.
- **The credential path redirected.** An `apiKeyHelper` or equivalent credential/API-key helper pointed at an external or newly written script, or a model endpoint or base URL swapped, routing the system's authentication or traffic through attacker-controlled code.
- **A guardrail or allowlist loosened.** A model safety or content guardrail downgraded or deleted (for example a Bedrock `DeleteGuardrail` or a guardrail `UpdateGuardrail` that removes filters), or an agent's tool or domain allowlist widened to permit destinations it previously blocked.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A confirmed owner whose role fits.** The actor is a known platform or AI-system admin whose role and prior history include this exact change, confirmed in the identity directory, not assumed from the account name.
- **A known automation identity.** A documented infrastructure-as-code or deployment service account with a steady baseline of these config edits, the platform maintaining itself.
- **The change tightens, not loosens.** A permission narrowed, a guardrail added, approvals enabled, hardening is hygiene, not this threat.
- **Baseline and window.** The same setting, actor, and change shape have run here before inside a known maintenance or change window.
- **Clean history.** This rule has closed benign on this actor before, with nothing new about who acted or which protection was touched this time.

To confirm a lead instead of guessing, pull the thread: after the config was weakened, did the same actor take an agent action that the removed guardrail would have caught, or make further loosening changes in the same window? Corroboration turns a suspicious config edit into a confirmed one.

# Output

## Decision
- **escalate:** a blanket tool permission, approvals turned off, the credential path redirected, or a guardrail or allowlist loosened by an actor who does not own the configuration, especially two together, or any one followed by an agent action the guardrail would have blocked.
- **dismiss:** a confirmed owner or known automation identity, acting inside a known window with a baseline match, explains it, and the change tightens rather than loosens, or a current, approved change owned by a confirmed owner or known automation identity accounts for the loosening. A dismiss is a positive call that the change is benign, made with that context in hand, an owner you confirmed in the directory, a window or baseline you actually saw the change fit; an actor you couldn't resolve or a change you couldn't place is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when an unexpected actor removes a safety, redirects credentials, or widens permissions, escalate.

## Evidence
The setting changed and the direction (toward less or more restriction), the actor and whether they are a confirmed owner, known automation, or unexpected, whether a credential helper or endpoint was redirected, the change window and baseline, any agent action that followed, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, an apiKeyHelper redirected to a newly written script by an ordinary user, followed by agent activity, is escalate on its own; a platform service account narrowing a permission on its usual cadence is dismiss.
