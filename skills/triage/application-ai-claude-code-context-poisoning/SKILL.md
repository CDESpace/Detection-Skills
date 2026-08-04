---
name: Application AI Claude Code Context Poisoning
description: Triage a Claude Code alert where the agent's trusted context is
  subverted through its own artifacts, CLAUDE.md, settings.json or
  settings.local.json, the .claude directory, hooks, or MCP configuration, read
  against the Claude Code telemetry (session, operation, decision, event_name).
  Reads which trusted file or capability changed, whether a user prompt drove
  it, and whether the change plants execution, weakens permissions, or wires in
  a tool, to tell normal developer edits apart from poisoning of the agent's
  trusted context, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - claude-code
    - persistence
---

# Triage Steps

This class fires on changes to the files and capabilities Claude Code implicitly trusts, CLAUDE.md instructions, settings.json and settings.local.json, the .claude directory, hooks, and MCP servers. Developers edit these constantly as normal work, so the fact that one changed is not the signal. The signal is what the change does to the agent: instructions that plant command execution or override safety, settings that grant blanket permissions or redirect the credential helper, a hook or MCP server wired in from an untrusted source, or an agent action with no user prompt behind it. Because Claude Code reloads and trusts these every session, a poisoned context persists and steers the agent quietly. Triage here reads the Claude Code telemetry to see which trusted surface changed and whether a human drove it. This class is the Claude-Code-specific view of context poisoning; the general patterns are covered by Application AI Prompt Injection, Application AI Guardrail Config Tampering, and Application AI Tooling Supply Chain.

Begin with this detection's track record on this user and host, a rule that fires on a developer's normal project setup and is always closed benign starts the call near dismiss, then read the Claude Code telemetry for the leads below. None is required on its own; they stack, and a single strong one (CLAUDE.md gaining a command-execution primitive) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **CLAUDE.md gaining execution or override content.** A `tool_result` with `operation` Write or Edit on a CLAUDE.md path whose new content adds command-execution primitives (a reverse shell, an encoded command, download-and-run) or override/jailbreak instructions, planted guidance the agent runs or obeys every session.
- **Settings weakened.** A write to settings.json or settings.local.json that grants a wildcard tool permission (`Bash(*)` or a bare `"*"`), sets the mode to bypass permissions, redirects `apiKeyHelper` to an external script, or embeds a hardcoded credential, the agent's brakes and identity path altered.
- **An untrusted capability wired in.** An `mcp_server_connection` to an unvetted or offensive-tooling server, a plugin from an unofficial marketplace, or a hook registered from an unofficial source, new power added to the agent from outside the approved set.
- **An agent action with no recorded user prompt, alongside a poisoned file.** A tool call or external reach in a `session.uid` with no `user_prompt` event. Treat this as corroboration for a poisoned-context finding, not a trigger alone: Claude Code sessions in an editor are non-interactive and frequently omit `user_prompt`, so a missing prompt is common in ordinary use.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A prompt and a developer explain it.** A user-prompt turn in the same session precedes the change, made by a confirmed engineer whose role and project fit the edit.
- **A benign, in-baseline edit.** The CLAUDE.md or settings change is ordinary project configuration the team makes routinely, matching this repo's and user's baseline, with no execution content, permission widening, or credential redirect.
- **An approved capability.** The MCP server, plugin, or hook is a first-party or approved-catalog component, its source known and its capability bounded.
- **The change tightens or is neutral.** A permission narrowed, a guardrail added, or documentation-only edits, not a loosening or a planted primitive.
- **Clean history.** This rule has closed benign on this user or repo before, with nothing new about the file, capability, or prompt context this time.

To confirm a lead instead of guessing, pull the thread: after the trusted file or capability changed, did the agent run a command, reach an external destination, or act without a prompt in the same session? Corroboration turns a suspicious edit into confirmed poisoning.

# Output

## Decision
- **escalate:** CLAUDE.md gaining execution or override content, settings weakened (wildcard permission, bypass mode, redirected credential helper, hardcoded secret), or an untrusted MCP server, plugin, or hook wired in, especially a poisoned file followed by the agent acting on it. A missing user prompt corroborates but does not escalate on its own, since editor sessions often omit the prompt event.
- **dismiss:** a user prompt and a confirmed developer, a benign in-baseline edit, or an approved capability explains it, and the change plants no execution, widens no permission, and redirects no credentials. A dismiss is a positive call that the change is benign, made with that context in hand, a developer and prompt you confirmed, a baseline you actually saw the edit fit; a change whose author or intent you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when a trusted file gains execution or override content, settings are weakened, an untrusted capability is added, or the agent acts with no prompt, escalate.

## Evidence
The trusted surface that changed (CLAUDE.md, settings.json / settings.local.json, .claude, hook, or MCP server), the operation and the new content or setting, whether a user prompt preceded it in the session, the acting user and whether they are a confirmed developer, any agent action that followed, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, a CLAUDE.md edit adding an encoded command with no user prompt in the session is escalate on its own; a developer updating project instructions after a matching prompt, with no execution content, is dismiss.
