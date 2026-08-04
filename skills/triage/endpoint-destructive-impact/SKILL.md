---
name: Endpoint Destructive Impact
description: Triage a host alert where data, backups, or the ability to recover
  is being destroyed, or service is being denied — recovery copies deleted or
  disabled, boot or recovery configuration tampered, mass encryption or
  overwriting underway, a process or service kill sweep, or a ransom note
  present. Reads which process is doing the destroying and what else fired
  alongside it to tell a change-managed backup or maintenance job apart from an
  active wiper or ransomware, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - ransomware
    - destruction
    - backup-deletion
    - impact
---

# Triage Steps

This is the highest-urgency class on the endpoint: the actions here are irreversible, so the cost of missing an active wiper or ransomware deployment dwarfs the cost of a false escalation on a backup rotation. Backup software legitimately deletes old recovery copies and VM lifecycle jobs legitimately remove disks, so the destructive action by itself is not the signal — the signal is which process is doing it and what else is firing on the host in the same window. Triage here is reading that pairing and deciding whether this is scheduled maintenance touching its own managed copies or an unexpected process taking away the ability to recover. When in doubt, escalate and let the investigation sort out a benign rotation.

Start from this detection's track record on this process and host — a backup job that rotates copies nightly and always closes benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and one strong lead (an unexpected process deleting shadow copies, a ransom note next to a rename burst) can carry the call. When mass log clearing co-fires with these destruction signals, this skill owns the compound sequence; the evasion-tampering skill defers to this class for that combination.

**Leads that point to a real threat** — what to look for in the data:

- **Recovery destroyed by the wrong process.** Removing or disabling recovery copies, backup catalogs, or the OS recovery path: `vssadmin delete shadows /all /quiet`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled no`. When the deleting process is not a recognized backup or recovery-management component — a backup agent, or the OS's own shadow-copy or disk-cleanup task — with a matching recurring entry in this host's baseline, this is the single most reliable tell — escalate without needing further evidence.
- **Mass overwrite or wipe.** File overwrites with constant or random content, a secure-erase utility run on a non-backup host, or a rapid directory-tree deletion outside a maintenance window. These can be quieter than encryption because they may not produce rename bursts, but their irreversibility makes them just as urgent.
- **Encryption in progress.** A burst of file renames or extension changes across many directories, a single process opening and rewriting files in rapid succession, or a ransom note file written into folder after folder (`README_RECOVER.txt` and the like).
- **A multi-step destruction sequence.** Recovery-copy deletion alongside mass encryption or overwrites, a log clear, a process or service kill sweep (`taskkill /F`, a `net stop` of databases or security services), or a ransom note in the same host window. Even if each alert looks explainable alone, the sequence together is an active kill chain and escalates.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A recognized recovery-management process on record.** The deletion comes from the backup product itself, an endpoint-backup agent, or the OS's own shadow-copy or disk-cleanup task, running on the host it is expected to run on — a dedicated backup server confirmed by the asset inventory (Axonius), or the protected host itself — at a scheduled time, touching only its own managed copies, with a matching recurring entry in this host's baseline.
- **An orchestration-initiated VM lifecycle op.** A disk or snapshot deletion initiated by the provisioning or orchestration system rather than a user-interactive session, matching a scheduled decommission record, with no other host showing concurrent destructive signals.
- **It matches the host's baseline.** The same process performing the same rotation on the same schedule exists as known-good activity here already.
- **Nothing else in the window.** No encryption, tamper, kill sweep, or ransom note anywhere in the same host window — the deletion stands alone and a maintenance job accounts for it.

To confirm a lead instead of guessing, pull the thread: is the destructive process still running, did a rename burst or ransom note follow the recovery-copy deletion, and is the deleting process the backup software or something else? Corroboration separates a backup rotation from an active wiper.

# Output

## Decision
- **escalate:** recovery destroyed by anything other than a recognized, baseline-matched recovery-management process, a mass overwrite or wipe, encryption in progress, or a multi-step destruction sequence.
- **dismiss:** a scheduled, baseline-matched deletion by the backup product, an endpoint-backup agent, or the OS's own recovery-management task — on a dedicated backup server or the protected host itself — or an orchestration-initiated VM lifecycle op matching a decommission record, fully accounts for the activity, and no encryption, tamper, kill sweep, or ransom note appears in the window. A dismiss is a positive call that the destruction is benign, made with that context in hand — a recognized recovery-management process with a matching baseline, an orchestration record or lifecycle event you actually saw; a process you couldn't recognize or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; on a sensitive target, with any co-occurring destruction signal, when the benign context is missing, or you're unsure, escalate without waiting for more.

## Evidence
The process performing the destruction (a recognized, baseline-matched recovery-management process vs an unexpected one), the scope (an isolated recovery-copy delete vs a multi-step sequence of tamper, encrypt, kill sweep, or note), the target host role from the asset inventory (backup server, file server, domain controller, virtualization host, or workstation), and what else fired on the host in the same window.

## Reasoning
Name the leads that decided it and how they stacked — an unexpected process running `vssadmin delete shadows` next to a file-rename burst is escalate on its own, while the backup product rotating its own copies on schedule with nothing else in the window is dismiss.
