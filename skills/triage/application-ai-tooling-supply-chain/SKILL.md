---
name: Application AI Tooling Supply Chain
description: Triage an alert where an AI agent's capabilities are extended from
  an untrusted source, connecting an unvetted or unofficial MCP (Model Context
  Protocol) server, installing a plugin or IDE extension from an untrusted
  marketplace, registering a hook from an unofficial source, or wiring in a tool
  that grants offensive, execution, or high-privilege capability. Reads the
  source and reputation of the added component, the capability it grants, and
  who added it, to tell approved integrations apart from an attacker handing the
  agent new powers, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - application
    - ai
    - supply-chain
    - mcp
    - resource-development
---

# Triage Steps

This class fires on an AI agent gaining a new capability, an MCP server connected, a plugin or extension installed, a hook registered. Developers add sanctioned tools to their agents constantly, so the fact that a component was added is not the signal. The signal is the source and the power it grants: a server, plugin, or hook from an unvetted or unofficial origin, or a tool that wires exec, network, or cloud capability into the agent. Extending an agent from an untrusted source is how an attacker turns a sanctioned assistant into a delivery or exploitation platform driven by natural language. Triage here is reading where the component came from and what it can now do. This class owns the acquisition of the capability; using it to act is judged by Application AI Agent Action Abuse, and weakening the agent's own settings is judged by Application AI Guardrail Config Tampering.

Begin with this detection's track record on this user and agent, a rule that fires when developers connect their team's approved MCP servers and is always closed benign starts the call near dismiss, then read the leads below. None is required on its own; they stack, and a single strong one (an offensive-tooling server connected from an unknown source) can carry the call.

**Leads that point to a real threat**, what to look for in the data:

- **An unvetted MCP server connected.** A `mcp_server_connection` (or equivalent) to a server that is not on the org's approved list, a personal, unknown, or newly seen server name or endpoint, or one reached over an unusual transport, giving the agent tools no one reviewed.
- **A component from an untrusted marketplace or publisher.** A plugin or IDE extension installed from an unofficial marketplace or an unverified publisher, or a `plugin:`-scoped tool whose source is not the org's known catalog.
- **A high-capability or offensive tool.** The added component grants shell execution, arbitrary network egress, cloud API access, or matches known offensive or red-team tooling by name, capability that turns the agent into an attack platform, well beyond a read-only or productivity integration.
- **A hook registered from an unofficial source.** A lifecycle hook or automation wired into the agent from an unvetted source, so attacker code runs on the agent's events without a further prompt.

**Leads that rule it out**, benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A first-party or approved-catalog integration.** The MCP server, plugin, or extension is a vendor first-party component or one from the org's approved catalog, its publisher known and its reputation clean.
- **A confirmed developer adding a sanctioned tool.** A known engineer connecting a server or installing an extension that fits their role and their team's standard toolset, confirmed by identity and history.
- **Read-only or low capability.** The component grants only scoped read or productivity capability, documentation, search, a ticketing connector, not shell, broad network, or cloud write.
- **Baseline and fleet norm.** The same server, plugin, or hook already appears across the team's agents as normal, established tooling on a known cadence.
- **Clean history.** This rule has closed benign on this user or agent before, with nothing new about the component's source or capability this time.

To confirm a lead instead of guessing, pull the thread: after the component was added, did the agent invoke its tools, reach an external destination, or run a command through it in the same session? Corroboration turns a suspicious integration into a confirmed one.

# Output

## Decision
- **escalate:** an unvetted MCP server, a plugin or extension from an untrusted marketplace or publisher, a high-capability or offensive tool from an untrusted, newly introduced, or unexplained source, or a hook from an unofficial source, especially any of these followed by the agent using the new capability. A high-capability component from the approved catalog, added by a confirmed developer, is not escalated on capability alone.
- **dismiss:** a first-party or approved-catalog integration, a confirmed developer adding a sanctioned tool, or a read-only low-capability component explains it, and the source is known and the capability bounded. A dismiss is a positive call that the addition is benign, made with that context in hand, a publisher and catalog you verified, a developer and toolset you confirmed; a component whose source you couldn't resolve or whose capability you couldn't bound is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the source is untrusted or unknown, the capability is high, or the tool is offensive, escalate.

## Evidence
The component added (MCP server, plugin, extension, or hook) and its source or publisher, the org's approval status for it, the capability it grants (read-only vs shell, network, cloud), the actor and whether they are a confirmed developer, any use of the new capability that followed, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked, an MCP server matching offensive tooling connected from an unknown source and then invoked is escalate on its own; a developer connecting the team's approved documentation server is dismiss.
