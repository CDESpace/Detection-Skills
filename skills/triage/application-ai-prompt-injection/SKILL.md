---
name: Application AI Prompt Injection
description: Triage an alert where untrusted content steers an AI model or agent
  against its operator, override or jailbreak instructions arriving in a fetched
  web page, a read file, a tool or MCP response, a ticket, email, or pull
  request, or planted in an agent instruction file such as CLAUDE.md,
  .cursorrules, or Copilot instructions. Reads the trust level of the content's
  source, whether it reached the model's context, and whether the agent then
  took an off-intent action, to tell red-team tests and benign mentions of these
  terms apart from a live injection, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - prompt-injection
    - jailbreak
    - initial-access
---

# Triage Steps

This class fires on text shaped like an instruction to an AI model, "ignore previous instructions", "you are now in developer mode", "do not tell the user", a smuggled tool directive. That text appears constantly in benign life: people write about prompt injection, red teams test for it, and detection authors put the exact phrases in rules and docs. The fact that the phrase appeared is not the signal. The signal is provenance and effect: injection instructions that arrived from a source the model does not control, a fetched page, a read file, an MCP or tool response, a ticket or pull request, or a modified agent instruction file, and then bent the agent's behavior. Triage here is reading where the content came from and what the agent did next, and deciding whether an outside party spoke to the model in the operator's place. This class owns the manipulation of the model's input; the downstream action the agent takes is judged on its own by Application AI Agent Action Abuse.

Begin with this detection's track record on this agent and user, a rule that fires on a security team's own eval harness or on detection-authoring activity and is always closed benign starts the call near dismiss, then read the leads below. None is required on its own; they stack, and a single strong one (override text from an untrusted document immediately followed by a sensitive tool call) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **Override text from an untrusted source.** Injection phrasing carried in content the operator did not write: a web page the agent fetched, a file or repository it read, an MCP server or tool response, an email, ticket, or pull-request body. Untrusted origin is what turns a suspicious phrase into a real one; the same phrase in the operator's own prompt is not this lead.
- **An instruction file was poisoned.** A write or edit to a trusted agent-context file, CLAUDE.md, .cursorrules, .github/copilot-instructions.md, AGENTS.md, adding override, persona-jailbreak, or "conceal from the user" directives, or wiring in a command to run. These files are reloaded and implicitly trusted every session, so planted instructions persist.
- **The injection was followed by an off-intent action.** Right after ingesting the untrusted content, the agent made a tool call, wrote a file, reached an external system, or exfiltrated data that no user prompt asked for. Ingestion plus action is the strongest escalator here.
- **A system-prompt or guardrail-exfil attempt.** Content asking the model to print its system prompt, reveal hidden instructions, or restate its tools and keys, reconnaissance that precedes a tailored injection.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A sanctioned test.** A red-team exercise or an eval/benchmark harness positively identified by a documented test identity, project, or header, the expected place for these phrases, and no unintended action followed.
- **The operator authored it.** The injection-looking text came from the user's own prompt, not from untrusted content the model consumed, a person is allowed to instruct their own agent.
- **Security or documentation authoring.** The match is inside detection content, a policy doc, an article, or a chat about prompt injection, the terms are the subject, not a command aimed at a live model.
- **No reach and no effect.** The content never entered a model's context, or it did and the agent took no action beyond it, a match in a stored file that was never loaded is not an injection.
- **Clean history.** This rule has closed benign on this agent or user before, with nothing new about the content's source or the action that followed.

To confirm a lead instead of guessing, pull the thread: after the untrusted content was ingested, did the agent call a tool, write to a sensitive path, or reach an external destination in the same session? Corroboration turns suspicious text into a confirmed injection.

# Output

## Decision
- **escalate:** override or jailbreak instructions that arrived from an untrusted source, a poisoned agent instruction file, or a system-prompt exfil attempt, especially any of these followed, close in time, by an off-intent agent action in the same session.
- **dismiss:** a verified red-team or eval test, the operator's own prompt, or security/documentation authoring explains the match, and no untrusted content reached a model that then acted on it. A dismiss is a positive call that the content is benign, made with that context in hand, a test identity you verified, an author and source you actually confirmed; content whose source you could not resolve, or that reached the model and was followed by an action, is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the source is untrusted or unknown, an instruction file was changed, or an action followed, escalate.

## Evidence
The injected text and where it came from (fetched URL, file or repo, MCP or tool response, message, or instruction file), whether it reached a model's context, any agent action that followed in the same session, whether a test identity or documented author accounts for it, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, override text pulled from an untrusted web page that was immediately followed by a file write is escalate on its own; the same phrase inside a detection rule authored by the security team is dismiss.
