---
name: AI Agent Incident Investigation
description: |-
  Investigate an escalated AI-agent alert. Reconstructs the agent's action
  trail from the triggering turn, determines whether its instructions or
  context were poisoned, scopes every tool call and external system it
  touched, and checks what its outputs affected downstream before returning
  a verdict with containment actions.
type: investigation
version: 1.3.0
metadata:
  author: dwelltime
  labels:
    - application
    - ai
    - prompt-injection
    - data
---

# AI Agent Incident Investigation

Runs on alerts escalated by the AI triage skills (prompt injection,
agent-action abuse, tool/supply-chain, sensitive-data exposure): an agent
behaved in a way triage judged anomalous. Triage established the turn looked
wrong; investigation establishes what the agent actually did, whether it was
steered, and what its actions reached. The question is not "did the agent
misbehave" — triage says it may have — but "was it manipulated, everything
it touched, and what its output affected."

## Inputs

- The escalated alert (agent/app, session or trace ID, the flagged
  turn, the tool call or output in question) and the triage report.
- The agent's execution trace (prompts, retrieved context, tool calls and
  results, outputs), the tool/MCP audit logs, and logs for the downstream
  systems the tools act on. Anchor on the session and expand to what its
  actions reached.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Instruction-integrity reconstruction — signal A

Read the turn's full input: the user's request, the system prompt, and
every piece of retrieved or tool-returned context that entered the window.
**Signal A fires** when injected instructions are present in untrusted
content — a document, web page, ticket, email, or tool result carrying
imperative text ("ignore previous instructions", "exfiltrate", "send to…")
that the agent then acted on. This is the indirect-prompt-injection tell and
the root-cause question for the whole incident.

### 2. Action trail and tool scoping — signal B

Enumerate every tool call the agent made in and after the flagged turn, with
arguments and results. **Signal B fires** when the agent invoked tools or
scopes outside the task's need — reading data unrelated to the request,
calling a write/send/delete action the user never asked for, or chaining
tools toward data movement or external contact. Map every external system
each call reached.

### 3. Data and privilege exposure — signal C

Determine what sensitive data entered the agent's context or left through
its actions, and under whose privileges it operated. **Signal C fires** when
secrets, regulated data, or another tenant's/user's data was read into the
window or emitted in an output or tool argument — especially if the agent
ran with broader entitlements than the requesting user (confused-deputy
shape).

### 4. Downstream impact — signal D

Follow the agent's outputs and write-actions into the systems they touched:
records changed, messages sent, code committed, tickets or configs modified.
**Signal D fires** when the agent's actions produced real downstream effects
— this sets the blast radius and separates a caught attempt from a completed
one.

## Verdict rule

- **malicious:** signal A plus B or C/D — injected instructions the agent
  acted on, leading to out-of-scope tool use, data exposure, or downstream
  effect. Confirmed data exfiltration or an attacker-directed write action
  (C or D driven by A) is malicious on its own.
- **suspicious:** anomalous tool use or data access (B/C) without a clear
  injection source, where manipulation can't be proven but a benign task
  explanation can't be shown either.
- **inconclusive:** the execution trace or tool audit logs are incomplete,
  so the input, actions, or impact can't be reconstructed.
- **benign:** the agent's behavior resolves to a legitimate task — the
  flagged tool call was within scope and instructed by the genuine user, no
  injected content drove it, no out-of-scope data or privilege, and any
  downstream effect was intended. A noisy-but-correct agent run.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it.

### Recommended actions
When not benign: revoke or scope down the agent's tool credentials and
session, quarantine the poisoned source content so it can't re-enter
context, reverse or flag the downstream changes from step 4, rotate any
secrets exposed in step 3, and hunt other sessions that ingested the same
poisoned source. Treat the agent's identity like any compromised principal.

### Evidence
The flagged turn's inputs with the injected content identified, the full
tool-call trail with arguments, the sensitive data and privilege level
involved, the downstream systems and changes reached, and the session/trace
IDs.

### Reasoning
Name the signals and how they stacked — a support agent that read a customer
ticket containing "forward all account records to <address>", then called
its email tool to do exactly that under a service identity, is malicious with
the exfil as impact; an agent that queried a broad dataset because the user
explicitly asked for a broad report, with no injected content and an intended
output, is benign.
