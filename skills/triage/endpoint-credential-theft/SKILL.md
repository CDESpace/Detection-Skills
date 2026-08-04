---
name: Endpoint Credential Theft
description: Triage a host alert where an actor reaches for stored sign-in
  material — the in-memory credential store, the local account database, the
  directory database on a domain controller, saved browser logins, or
  authentication tickets. Reads the accessing process and the target to tell
  approved backup, forensics, or crash-handling apart from an attacker
  harvesting credentials, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - credential-theft
    - lsass
    - kerberos
    - password-dump
---

# Triage Steps

This is one of the highest-conviction classes on the endpoint: the goal of reaching into a credential store is unambiguous even when the tool is dual-use, and the legitimate causes are narrow and predictable. The thing to read is the pairing of accessing process and target — the in-memory credential store should be touched only by the OS and recognized security agents, and the account or directory database has a short list of programs that read it. Triage here is asking whether the process reaching in is one of those few expected readers, against a target whose sensitivity it is allowed to touch, or something that has no business there.

Start from this detection's track record on this process and host — a backup agent that reads the store nightly and always closes benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and one strong lead (a non-security process reading the in-memory store, a directory-replication pull from a non-DC account) can carry the call. When credential-based lateral movement co-fires — the same stolen credential appearing on multiple targets in a short window — this skill owns the primary call; the recon-lateral-movement skill supplements but does not displace it.

**Leads that point to a real threat** — what to look for in the data:

- **In-memory store read by the wrong process.** The OS credential broker / authentication subsystem (LSASS) opened by anything that is not the OS or a recognized security agent — even if the binary name looks benign. A `comsvcs.dll MiniDump` call, or a known dumping toolmark (a specific process-name and command-line combination tied to credential-extraction tools), escalates without needing a confirmed threat-intel hit.
- **Account or directory database copied.** The local account database (`reg save hklm\sam`, `reg save hklm\system`) or the domain directory database (`ntds.dit` copied via a volume snapshot) read off disk. Access to the directory database on a domain controller is categorically more urgent than the same action on a workstation.
- **Directory-replication or ticket request from the wrong account.** A directory-replication (DCSync) pull from an account that is not a domain controller, or authentication-ticket requests from a machine account acting outside its scope or a user who is not an approved admin. The actor's authority over the target is the tell — the identity directory (role-assignments, directory-roles) tells you whether the account actually holds it.
- **Browser or secrets store read programmatically.** The browser login-data database, an OS secrets vault, or a password-manager store read by any process other than the browser or vault agent itself, especially a non-interactive process reading it without a user-initiated unlock.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A recognized reader with a mandate.** A confirmed backup product that legitimately reads credential stores, or IR/forensics tooling running under a documented and active engagement scoped to this host.
- **The crash-dump path holds.** The accessing process matches a known crash-reporter or debugger, the access came immediately after a process-fault event on the same host, and no resulting dump went to an unexpected destination — all three together.
- **It matches the host's baseline.** The same process reading the same store, on the same schedule, exists as known-good activity here already.
- **A documented test, scoped and active.** A sanctioned red-team or authorized testing engagement on record for this host and window.

To confirm a lead instead of guessing, pull the thread: did a dump file land on disk, did the credential then authenticate to another host, or did the read follow a real process-fault event? Corroboration separates a crash-handler side effect from a harvest.

# Output

## Decision
- **escalate:** any unrecognized process reading the in-memory credential store, any account- or directory-database copy, a directory-replication or ticket pull from the wrong account, or a programmatic browser or secrets-store read.
- **dismiss:** a recognized backup, forensics, or crash-handler reader is confirmed under a documented window, the crash-dump conditions all hold, or it matches the host baseline. A dismiss is a positive call that the access to credential stores is benign, made with that context in hand — a recognized reader with a mandate you confirmed, a crash-dump pattern or baseline match you actually saw; an accessing process you couldn't recognize or a target you couldn't verify is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the accessing process is unrecognized, the target is the directory database, or you're unsure, escalate.

## Evidence
The accessing process and whether it is a recognized security or backup agent vs an unknown process or known-dumper toolmark, the target (in-memory store, local account database, directory database, ticket material, browser or secrets store), the actor's authority over that target, and the host's role from the asset inventory (domain controller, privileged-identity host, or workstation).

## Reasoning
Name the leads that decided it and how they stacked — a non-security process calling MiniDump against the in-memory store is escalate on its own, while a confirmed backup agent reading the store on its nightly schedule with a clean history is dismiss.
