---
name: Application AI Sensitive Data Exposure
description: Triage an alert where sensitive data flows into or out through an
  AI model or service, prompts or agent context carrying secrets, credentials,
  PII, or source code; bulk data pulled into an AI tool's context and sent to a
  third-party model endpoint; or code and data exfiltrated through an agent's
  web fetch or tool output. Reads the data class, the destination, the volume,
  and the actor's baseline, to tell sanctioned internal AI use apart from
  sensitive data leaving through a model, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - exfiltration
    - data-exposure
    - collection
---

# Triage Steps

This class fires on data moving through an AI system, text sent to a model, files pulled into an agent's context, content returned by a tool. People feed data to AI assistants all day as sanctioned work, so the fact that data reached a model is not the signal. The signal is what the data is and where it went: secrets or regulated data in a prompt, a bulk pull of source code or records sent to a third-party model endpoint, sensitive content carried out through an agent's web fetch or tool output. This is data exfiltration wearing the shape of ordinary AI usage. Triage here is reading the data class, the destination, and the volume against the actor's baseline, and deciding whether this is sanctioned internal use or sensitive data leaving. This class owns the data movement through the AI channel, distinct from a general SaaS share or download, which is judged by Application Data Exfiltration Oversharing.

Begin with this detection's track record on this actor and workload, a rule that fires on an approved internal AI application and is always closed benign starts the call near dismiss, then read the leads below. None is required on its own; they stack, and a single strong one (a secret or a bulk source-code payload sent to an external model) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **Secrets or regulated data in the prompt or context.** A prompt or agent context carrying an API key, credential, private key block, or PII/regulated records, sensitive material handed to a model that logs, retains, or trains on it.
- **A bulk pull sent to a third-party model.** A large volume of source code, documents, or records read into an agent's context and sent to an external or consumer model endpoint rather than a sanctioned internal one, data leaving the trust boundary through the model channel.
- **Exfil through an agent's egress.** Sensitive content carried out via an agent's web fetch, tool output, or an external destination the model was steered to reach, the model or agent acting as the exfiltration path.
- **An unsanctioned or consumer endpoint.** Data flowing to a personal or consumer AI service, an unapproved model provider, or an off-baseline external endpoint for that actor, rather than the organization's approved AI platform.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A sanctioned internal model within policy.** The data went to the organization's approved AI platform or a private model, used within a documented policy for that data class.
- **A known workload in baseline.** A documented application or service account whose baseline includes exactly this data flow and volume, the workload doing its job, confirmed by identity and history.
- **Non-sensitive data.** The content is public, synthetic, or low-sensitivity, with no secrets, credentials, or regulated records, volume alone to an approved endpoint is not this threat.
- **Destination is internal and approved.** The endpoint is the org's sanctioned model, not a consumer or unapproved third-party service.
- **Clean history.** This rule has closed benign on this actor before, with nothing new about the data class, destination, or volume this time.

To confirm a lead instead of guessing, pull the thread: what was the data class, did it go to an approved internal model or an external one, and did the same actor move more of it in the same window? Corroboration turns a suspicious flow into a confirmed exposure.

# Output

## Decision
- **escalate:** secrets or regulated data sent to an external or unsanctioned model, a bulk pull sent to a third-party model, exfil through an agent's egress, or sensitive data reaching a consumer or unapproved endpoint, especially a volume spike off baseline. Sensitive data handled by a sanctioned internal model within policy is not escalated on content alone; the destination outside the trust boundary or the policy violation is what escalates.
- **dismiss:** a sanctioned internal model within policy, a known workload in baseline, or non-sensitive data to an approved endpoint explains it, and no secrets or regulated data left the trust boundary. A dismiss is a positive call that the flow is benign, made with that context in hand, a destination you confirmed as internal and approved, a data class and baseline you actually saw; a destination you couldn't resolve or a data class you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when sensitive data reaches an external or consumer model, or volume spikes off baseline, escalate.

## Evidence
The data class (secret, credential, PII, source code, or non-sensitive), the destination (approved internal model vs third-party or consumer endpoint), the volume against baseline, the actor and whether the workload is documented, the AI channel used (prompt, context pull, or agent egress), and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, a bulk source-code payload sent to a consumer model endpoint by an ordinary user is escalate on its own; an approved internal assistant handling its normal document load within policy is dismiss.
