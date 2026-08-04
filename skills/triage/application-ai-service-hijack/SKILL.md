---
name: Application AI Service Hijack
description: Triage an alert where a hosted AI or LLM inference service is
  abused through compromised credentials (LLMjacking), enabling or requesting
  foundation-model access, a spike of unauthorized inference, model-availability
  or validation-error recon bursts, or new API-key creation for an AI service,
  across Amazon Bedrock, Google Vertex AI, or Azure OpenAI. Reads whether the
  calling identity has ever used the service, model-access enablement by an
  unexpected principal, and inference volume and cost against baseline, to tell
  ML-platform automation apart from an attacker renting stolen compute, and
  decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - llmjacking
    - cloud
    - impact
---

# Triage Steps

This class fires on control-plane and inference calls to a managed AI service, enabling a model, invoking one, listing what is available. Data teams and applications do this legitimately every day, so the fact that a Bedrock or Vertex or Azure OpenAI call happened is not the signal. The signal is the shape and the actor: a principal that never touched the AI service suddenly enabling model access and driving inference, a spend or volume spike well past baseline, recon that maps which models are reachable, the pattern of someone monetizing stolen credentials on the victim's inference bill. Triage here is reading who called, whether they belong to the AI service, and whether the volume and the enablement step look like adoption or abuse. This class owns the abuse of the AI service's own APIs; stolen-credential signals elsewhere are judged on their own.

Begin with this detection's track record on this identity and account, a rule that fires on a known ML-platform service account or an AI team's workload and is always closed benign starts the call near dismiss, then read the leads below. None is required on its own; they stack, and a single strong one (model-access enablement by an identity that has never used the service, followed by an invocation burst) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **Model access enabled by a first-time principal.** An identity with no history on the AI service crossing the access "speed bump": `PutUseCaseForModelAccess`, `CreateFoundationModelAgreement`, or `PutFoundationModelEntitlement` on Bedrock, or the analogous enablement, entitlement, or deployment grant on Vertex AI or Azure OpenAI, each of which uses its own flow. Enabling a model you have never used is the attacker's first move.
- **An inference volume or cost spike.** A sharp rise in `InvokeModel` / `InvokeModelWithResponseStream` (or the platform equivalent) against the identity's and account's baseline, sustained, high-token, or high-cost calls that do not match any known workload.
- **Reconnaissance bursts.** `GetFoundationModelAvailability`, `ListFoundationModels`, or repeated validation errors from probing model IDs and regions, mapping which models are reachable before abuse, often from an identity that otherwise never queries the service.
- **A fresh key or role feeding inference.** A new access key or role created and then immediately used to enable or invoke models, or model calls arriving from an off-baseline source IP or region for that identity.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A known ML-platform identity.** A documented data-science or application service account whose baseline includes exactly these model calls, the workload doing its job, confirmed by identity and history, not by the account name alone.
- **Documented onboarding.** A model-access enablement that matches a recorded change or a team standing up a new use case inside a known window.
- **In-baseline volume.** The invocation rate, models, and regions match this identity's established pattern, a production app serving its normal inference load.
- **Recon that fits.** Availability or model-list calls from a console or SDK session by an identity that routinely manages the service, not a probing burst from an unexpected principal.
- **Clean history.** This rule has closed benign on this identity before, with nothing new about the actor, the volume, or the enablement step this time.

To confirm a lead instead of guessing, pull the thread: after model access was enabled, did an invocation burst follow, did the identity call from an unusual source, or did other stolen-credential activity appear in the same window? Corroboration turns a suspicious call into confirmed hijacking.

# Output

## Decision
- **escalate:** model access enabled by an identity that has never used the service, an inference volume or cost spike off baseline, a reconnaissance burst, or a fresh key driving model calls, especially enablement followed by an invocation burst.
- **dismiss:** a known ML-platform identity, documented onboarding, or an in-baseline invocation load explains it, and no unexpected principal enabled access or drove an off-baseline spike. A dismiss is a positive call that the usage is benign, made with that context in hand, a workload identity you confirmed, a baseline you actually saw the calls fit; an actor you couldn't place on the service or a volume you couldn't baseline is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when an unexpected identity enables model access, volume spikes, or a fresh key drives inference, escalate.

## Evidence
The AI service and API called, whether the identity has prior history on the service, any model-access enablement step and who performed it, inference volume and cost against baseline, the source IP and region, whether a fresh key or role fed the calls, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, a principal with no Bedrock history enabling model access and then running an InvokeModel burst is escalate on its own; a documented data-science service account serving its normal inference load is dismiss.
