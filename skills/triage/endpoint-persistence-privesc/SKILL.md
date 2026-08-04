---
name: Endpoint Persistence Privesc
description: Triage a host alert where something has set up a foothold that
  survives reboot or grabbed higher privilege — a new service, a scheduled task,
  an autostart entry, an event-triggered hook, a DLL dropped into a search path,
  a consent-prompt bypass chain, or an on-host or domain-controller-observed
  privileged-group or rights change. Reads who created the mechanism and where
  its payload lives to tell routine installer and deployment churn apart from an
  attacker entrenching or elevating, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - persistence
    - privilege-escalation
    - foothold
    - autoruns
---

# Triage Steps

This class fires on actions that real software performs all day — installers register services, deployment tools create scheduled tasks, agents write run-key entries, and admins add accounts to privileged groups. Installer churn is the loudest benign source here, so the fact that a persistence mechanism was written is not the signal. The signal is who wrote it and what it points at: a known deployment tool pointing a well-named service at its own signed binary reads very differently from an unexpected account pointing a task at a script in a temp folder. Triage here is reading that pairing and deciding whether this is a managed change or someone planting a foothold or quietly elevating.

Start from this detection's track record on this actor and host — a rule that fires on every patch cycle and always closes benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and one strong lead (a worker process writing a web shell, an unsigned DLL dropped ahead of a load) can carry the call. When a web shell write co-fires with a defense-evasion tamper alert on the same host, the evasion-tamper skill owns the call only if tampering is the primary act; persistence owns it when the write itself is the primary signal.

**Leads that point to a real threat** — what to look for in the data:

- **Unexpected actor creating the mechanism.** A low-privilege user, a service account, or a SYSTEM context spawned by an odd parent registering persistence: `sc create svc binPath= C:\Users\Public\x.exe`, `schtasks /create /ru SYSTEM /tr ...` from a non-admin shell. The actor's role, not the mechanism, is the tell — real persistence is created by deployment tooling and admins.
- **Payload in a writable or wrong place.** The service, task, or `Run`-key value points at an unsigned binary, a renamed system tool, or a script interpreter whose argument is a script sitting under `\Temp`, `\Downloads`, `%PUBLIC%`, or `C:\ProgramData` instead of a vendor install path: `reg add HKCU\...\Run /v upd /d "%TEMP%\a.vbs"`. A malicious or suspicious verdict on the payload's hash makes the wrong-place read decisive; unexpected actor plus a payload in a writable location is escalate.
- **Library search-order drop.** An unsigned or unrecognized DLL placed in a directory that takes load precedence over the real path, not explained by any software deploy, especially one written just before or after another odd event on the host. When a process then loads from that path, the pair is escalate without further conditions.
- **Bypass or rights grant with no visible approval.** A consent-prompt or auto-elevation chain that skips the approval step (`fodhelper.exe`, an env-var hijack feeding an auto-elevating binary), or a high-privilege group add or sensitive-right grant observed on the host or its domain controller outside a change window — adding an account to a local or Active Directory group, or granting it the ability to act for other accounts on this host. The bypass pattern itself is the escalator.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A confirmed admin or a deployment/management service account whose role and history include creating this exact mechanism on this host — the identity directory (Graph/Okta users, directory-roles) confirms the role, not the account name.
- **It matches the host's baseline.** The same service, task, or run-key entry, with the same payload path, exists as a known-good entry here already.
- **Signed payload in its install path.** The service or task points at a vendor-signed binary under `C:\Program Files\...`, not a copy dropped in a user or temp folder.
- **Fleet-wide, not single-target.** The identical mechanism and payload path appear across many hosts on a deploy or patch cadence — the shape of management, which rolls out broadly; an intrusion plants on one or a few.
- **Clean history with a deploy that fits.** This rule has closed benign on this host before, and a software install or patch cycle on record explains the timing this time.

To confirm a lead instead of guessing, pull the thread: did the registered binary later run, did a process load from the dropped path, or did the newly privileged account take an action in the same window? Corroboration turns a suspicious write into a confirmed foothold.

# Output

## Decision
- **escalate:** an unexpected actor creating the mechanism, a payload in a writable or wrong place, a search-order DLL drop, or a bypass or rights grant with no visible approval — especially two together, or any one followed by the payload running.
- **dismiss:** a confirmed admin or deployment service account, a baseline match, or a signed payload in its install path explains it, with a deploy or patch cycle that fits the timing and no writable-path payload or bypass pattern. A dismiss is a positive call that the mechanism is benign, made with that context in hand — a deployment account's install history you verified, a matching run-key entry you actually saw; an actor you couldn't confirm or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the actor or payload path looks wrong, nothing explains it, or you're unsure, escalate.

## Evidence
The actor creating the mechanism and its role, the mechanism type and where its payload lives (vendor install path vs temp or interpreter), whether it is a standard service or task vs a bypass chain or web shell, whether it matches the host baseline or a fleet-wide rollout, the host's role from the asset inventory (Axonius, managed-devices), and how this rule was handled here before.

## Reasoning
Name the leads that decided it and how they stacked — an unexpected account pointing a scheduled task at a temp-folder script is escalate, while a signed installer registering its own service across the fleet on a patch cadence is dismiss.
