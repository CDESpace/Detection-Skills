---
name: Windows Audit Blindness Triage
description: |-
  Triage the possibility that a Windows host's audit policy makes it lie
  before trusting any "nothing happened" answer from it. A host with
  Failure-only Logon auditing reports zero successful logons while an
  attacker sits on it; a host without 4688 command-line auditing returns
  empty process histories; a host without ScriptBlock Logging never shows
  PowerShell script content. Verify the audit sources the identity and
  execution questions depend on, read the blind spots by subcategory GUID
  so a non-English display language cannot fake sight, and return a
  per-source ok/BLIND map with the exact policy fixes before any finding
  from that host is believed.
type: triage
version: 1.0.0
metadata:
  author: DrOlu
  labels:
    - windows
    - audit-policy
    - telemetry
    - evidence-quality
    - visibility
---

# Windows Audit Blindness Triage

Run this whenever a Windows endpoint's answers feel too clean: zero
successful logons over days, an empty process history during a confirmed
intrusion window, no PowerShell content while the tip says PowerShell. The
most dangerous telemetry failure on Windows is not missing data — it is a
host that confidently reports emptiness because its audit policy was never
turned on, or was quietly narrowed. An empty answer from a blind host is
indistinguishable from a quiet host, and every downstream conclusion built
on it inherits the blindness.

The failure mode is real and common: Windows Server defaults to Failure-only
auditing for the Logon category, so every "who logged on successfully"
question returns nothing while failures keep flowing — the host looks alive
and secure while an attacker authenticates happily. Command-line auditing
(4688 with `IncludeCmdLine_Enabled`) is off by default on most builds, and
PowerShell ScriptBlock Logging (4104) is off unless a policy enabled it.

## Inputs

- Remote or local access to the Windows host (admin, or the ability to run
  `auditpol` and read two registry values).
- Optionally: the finding or empty result that raised suspicion.

## Triage steps

### 1. Read the audit policy by subcategory GUID, never by display name

`auditpol /get /category:* /r` emits CSV with a Subcategory GUID column.
Parse by GUID — matching the localized display name breaks on non-English
hosts and makes every entry read "unknown," which reports a clean blindness
count and the host looks sighted. The GUIDs that decide identity and
execution visibility:

| GUID prefix | Subcategory | Why it matters |
|---|---|---|
| `{0CCE9215-...}` | Logon | 4624 successful logons — the identity timeline |
| `{0CCE9216-...}` | Logoff | session end times |
| `{0CCE9217-...}` | Account Lockout | brute-force evidence |
| `{0CCE921B-...}` | Special Logon | privileged-token assignments |
| `{0CCE921C-...}` | Other Logon/Logoff | session reuse signals |

Read the Inclusion Setting column adjacent to the GUID cell (beware 80-column
console wrapping — pipe through a wide formatter or the row splits
mid-value). Each subcategory must include Success, or the corresponding
question returns permanently empty.

### 2. Check the two execution-visibility sources auditpol does not cover

Process command lines: read
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`.
Value 1 means 4688 events carry the command line; without it, process
history shows *that* something ran but never *what* — the LOLBin question
is unanswerable on this host.

PowerShell script content: read
`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging`.
Value 1 means 4104 events record script text. Without it, every obfuscated
PowerShell payload — encoded commands, download cradles — leaves no readable
trace. These two are the switches an attacker is most likely to leave off,
and the two most often off in a fresh estate.

### 3. Score and report per source, never as a single number

Emit one map: each source → `ok` / `BLIND` / `unknown`. Then apply the rule
that matters: **an empty answer is not a clean answer.** A host with any
BLIND source may still report "no findings" from its blind questions — that
is the policy succeeding, not the host being quiet. Any conclusion drawn
from a blind source must be labeled as such, and a host with Success-auditing
off for Logon cannot support *any* identity conclusion at all.

### 4. Fix, then re-verify by generating an event

The fix is policy, not tooling: `auditpol /set /subcategory:<guid>
/success:enable` for each blind subcategory, plus the two registry values
for 4688 command lines and 4104. New processes pick the PowerShell policy up
immediately. Close the loop end-to-end: generate a known event (run a
distinctive script block; make a successful logon), then re-read the log and
confirm the event appears. A policy change without a round-trip event is a
plan, not a fix.

# Output

## Action
**report** — a per-source visibility map for the host, plus the exact policy
commands for each BLIND source; escalate as critical when the host sits in
an active-investigation window, because every historical finding from its
blind sources is now suspect.

## Target
The Windows host's audit and logging configuration — auditpol subcategories,
the 4688 command-line value, the 4104 policy key.

## Evidence
The GUID-keyed auditpol rows with their Inclusion Settings, the two registry
values, and the post-fix round-trip event proving the host now records what
it was blind to.

## Reasoning
The mechanism, not the measurements: Windows audit policy decides what the
host is *capable of witnessing*, and a host cannot report what its policy
never recorded. Empty results from a blind source are policy artifacts, not
security signals — so visibility must be verified before any per-host
conclusion is trusted.
