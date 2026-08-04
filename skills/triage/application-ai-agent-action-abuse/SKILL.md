---
name: Application AI Agent Action Abuse
description: Triage an alert where an AI agent takes a consequential action
  outside its intended scope or with no human instruction behind it, running a
  shell command, writing to a sensitive path, spawning a subprocess, reaching an
  external system, or driving a cloud or SaaS API when no user prompt or
  approval preceded it, or the action exceeds the agent's sanctioned tools.
  Reads whether an interactive prompt preceded the action, the sensitivity of
  what was touched, and whether the session is human-driven or automated, to
  tell sanctioned agent workflows apart from an agent acting on its own, and
  decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - execution
    - prompt-injection
---

# Triage Steps

This class fires on actions an AI agent is built to take, Claude Code, a Cursor or Copilot agent, or an autonomous MCP client running a command, writing a file, or calling an API. Agents do this all day on their operators' behalf, so the fact that an agent acted is not the signal. The signal is intent and scope: an action with no human instruction behind it, or one that reaches past the tools the agent was sanctioned to use. An injected instruction or a hijacked session makes the agent act for someone other than its user, and the tell is that the action stands alone, no prompt asked for it, or the tool was never in scope. Triage here is reading whether a person drove this and whether the agent stayed in its lane. This class owns the action itself; the untrusted content that may have induced it is judged on its own by Application AI Prompt Injection.

Begin with this detection's track record on this agent and identity, a rule that fires on a sanctioned CI or automation agent and is always closed benign starts the call near dismiss, then read the session and the action for the leads below. None is required on its own; they stack, and a single strong one (an external tool call in a session with no user prompt on record) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **An action with no recorded user prompt, corroborating a sensitive or out-of-scope move.** A tool call, command, or external reach in a session with no user-prompt event before it. Treat this as corroboration, not a trigger on its own: interactive IDE sessions (for example Claude Code in an editor) and non-interactive sessions often do not emit a `user_prompt` event at all, so a missing prompt is common in benign work. It counts when it accompanies an out-of-scope tool, a sensitive target, or a reach to an unusual external destination.
- **Out of sanctioned scope.** The agent invoked a tool or capability outside its declared allowlist, a research or read-only assistant running a shell command, writing outside its workspace, or calling a cloud or SaaS write API it was never granted.
- **A sensitive target.** The action wrote to a persistence or system path, read a secret store, changed a permission or policy, or reached an external destination, the kind of move that matters even once, distinct from ordinary in-workspace edits.
- **An automated session reaching an unusual destination.** A headless or automated session making outbound tool calls or network reaches that its normal job does not explain. Non-interactive alone is not the signal, IDE sessions also report as non-interactive; the tell is a destination or action a known automation identity has no reason to produce.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A prompt drove it.** A user-prompt turn in the same session precedes the action and fits it, the operator asked, the agent did.
- **A sanctioned automation identity.** A documented CI, deployment, or agent service account with a steady baseline of exactly these actions, the pipeline doing its job, confirmed by identity and history, not by the account name alone.
- **In scope and in baseline.** The tool is within the agent's granted allowlist and the same action shape has run here before as normal work, an in-workspace file edit by a coding agent, a read the agent is meant to make.
- **A benign target.** The action stayed inside the agent's workspace or touched non-sensitive resources, with no reach to persistence paths, secrets, or external systems.
- **Clean history.** This rule has closed benign on this agent or identity before, with nothing new about the prompt context or the target this time.

To confirm a lead instead of guessing, pull the thread: did more unprompted actions, a reach to an unusual external destination, or a write to a sensitive path follow in the same session? Corroboration turns a suspicious action into a confirmed one.

# Output

## Decision
- **escalate:** an action outside the agent's sanctioned tools, reaching a sensitive target (persistence path, secret store, policy change), or reaching an unusual external destination, when no sanctioned automation identity explains it. A missing user prompt corroborates these but does not escalate on its own, since IDE and non-interactive sessions often omit the prompt event. Two leads together, or more sensitive actions after the first, raise confidence.
- **dismiss:** a user prompt in the same session, a sanctioned automation identity, or an in-scope in-baseline action explains it, and nothing reached persistence, secrets, or an external system without intent. A dismiss is a positive call that the action is benign, made with that context in hand, a prompt you saw precede it, an automation role you confirmed; a session whose prompt context you couldn't establish or a tool you couldn't place in scope is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when no prompt explains the action, the tool is out of scope, or the target is sensitive, escalate.

## Evidence
The action and its target (command, file path, API, or destination), whether a user prompt preceded it in the session, whether the tool is within the agent's sanctioned scope, whether the session is interactive or automated, the acting identity and whether it is sanctioned automation, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, an external tool call in an interactive session with no user prompt on record, reaching a destination the agent never uses, is escalate on its own; a build agent writing inside its workspace after a matching prompt is dismiss.
