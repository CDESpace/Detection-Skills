---
name: Endpoint Defense Evasion Tampering
description: Triage a host alert where the main act is weakening defenses or
  erasing evidence — disabling or excluding a security agent, stopping security
  logging, clearing event logs or command history, weakening a protective
  setting, or tampering with the scripting and tracing layers that feed
  detection. Reads who made the change and what fired alongside it to tell
  change-managed security maintenance apart from an attacker blinding the host,
  and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - defense-evasion
    - tamper
    - log-clearing
    - av-disable
---

# Triage Steps

This class fires on actions IT teams take on purpose — adding security-agent exclusions, updating protective policy, stopping an agent for maintenance — so the change by itself is not the signal. Centrally managed exclusions and routine agent maintenance are the loudest benign source, and exclusion changes in particular are genuinely noisy because many teams manage them through the registry or a config file. The signal is who made the change, what the change targets, and what else fired on the host in the same window. Triage here is reading those three together and deciding whether this is routine security upkeep or someone turning down the lights before, during, or after something worse.

Start from this detection's track record on this actor and host — a heuristic that fires on every policy push and always closes benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and one strong lead (a mass log clear, a log-forwarder stopped, tamper next to a credential dump) can carry the call. When mass log clearing co-fires with shadow-copy deletion or mass encryption on the same host, the destructive-impact skill owns that compound sequence; this skill defers to it when destruction co-signals are present.

**Leads that point to a real threat** — what to look for in the data:

- **Mass event-log clear.** Logs wiped, especially across several channels in a short window: `wevtutil cl Security`, `wevtutil cl System`, `Clear-EventLog`, or a command-history wipe. Clearing logs has no routine cause and is high-confidence tamper regardless of who the actor is.
- **Log-forwarder or telemetry agent stopped.** Stopping, reconfiguring, or uninstalling the component that ships events off the host — `net stop`, `sc config ... start= disabled`, or killing the forwarder service — kills downstream visibility. No non-administrative process has a sanctioned reason to do this; it is high-confidence on its own.
- **Exclusion pointing at a staging path.** A security-agent exclusion added for a temp directory, a known payload staging path, or a folder created moments earlier in the same session: an exclusion path under `\Temp`, `%PUBLIC%`, or a just-written directory. A malicious or suspicious verdict on the hash of any file already in the excluded path makes it decisive. The target is the tell — an exclusion for a payload path is a strong escalator, where one for a signed vendor product path is not.
- **Scripting and tracing layer tampering.** Disabling the scripting anti-malware interface or the event-tracing channels that feed detection (patching the in-memory check, disabling script logging). Blinding the layer that watches script execution has no benign automation reason.
- **Tamper alongside another tactic.** Any of the above firing in the same host window as a credential dump, a download-and-execute, or destructive signals is a kill-chain indicator and escalates regardless of the tamper rule's own confidence.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A confirmed security or IT-operations identity — the identity directory (Graph/Okta users, directory-roles) confirms the role — making the change on a host the asset inventory (Axonius, managed-devices) shows as its expected management host, within a recognizable maintenance pattern.
- **It matches a managed-policy baseline.** The change matches a known-good managed-policy entry for this host, or a vendor agent updating its own config under a documented install or update trigger.
- **Vendor path, signed target.** An exclusion or setting change that points at a signed vendor product path, not a temp or payload folder.
- **Fleet-wide, not single-target.** The identical exclusion or policy change lands across many hosts uniformly — the shape of a managed policy push, which applies broadly; tamper in an intrusion hits the one host the actor is on.
- **Clean history, nothing else in the window.** A historically high-volume heuristic consistently closed benign for this binary, with no credential, download, or destruction signal anywhere in the window.

To confirm a lead instead of guessing, pull the thread: did the excluded path soon host a process launch, or did a credential read, download, or file-rename burst follow the tamper in the same window? Corroboration turns a noisy exclusion into a confirmed cover-up.

# Output

## Decision
- **escalate:** a mass log clear, a log-forwarder or telemetry agent stopped, an exclusion pointing at a staging path, scripting or tracing layer tampering, or tamper firing alongside another tactic on the same host.
- **dismiss:** a confirmed security or IT actor on its management host, a managed-policy baseline match, or a vendor self-update with a documented trigger explains it, the change targets a signed vendor path, and nothing else fired in the window. A dismiss is a positive call that the change is benign, made with that context in hand — a recognizable maintenance pattern you matched, a fleet-wide policy push you actually saw; an actor you couldn't confirm or a baseline pattern you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the actor is unexpected, the target is a staging path, anything co-fires, or you're unsure, escalate.

## Evidence
The actor's role (security or IT-admin vs an unexpected process), the tamper type (log clear vs exclusion vs agent stop vs scripting or tracing tamper), what the change targets (vendor path vs temp or payload path), whether it matches a managed-policy baseline or a fleet-wide push, and what else fired on the host in the same window.

## Reasoning
Name the leads that decided it and how they stacked — tamper firing in the same window as a credential dump is escalate on its own, while a fleet-wide exclusion for a signed vendor path pushed by IT with nothing else in the window is dismiss.
