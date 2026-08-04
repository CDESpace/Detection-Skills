---
name: Lateral Movement Investigation
description: |-
  Investigate an escalated lateral-movement alert. Reconstructs the path an
  actor took between hosts — the source, the credentials used, the technique,
  and every asset reached — distinguishes admin or tooling traffic from an
  intruder pivoting, and returns a verdict with the full reached-asset scope
  and containment actions.
type: investigation
version: 1.1.0
metadata:
  author: ghostbyte
  labels:
    - endpoint
    - identity
    - lateral-movement
    - credential-access
---

# Lateral Movement Investigation

Runs on alerts escalated by triage (see `endpoint-recon-lateral-movement`):
a host made an internal connection — remote service creation, WMI/WinRM
execution, RDP, SMB admin-share access, or a pass-the-hash shape — that
triage judged anomalous. Triage established the hop looked wrong;
investigation reconstructs the whole path and its reach. The question is
not "did a host connect to another" — it did — but "who drove it, with
what credential, and everywhere it went."

## Inputs

- The escalated alert (source host, destination host(s), technique,
  account used, timing) and the triage report.
- Authentication logs (Windows `4624`/`4648`/`4672`, Kerberos, VPN),
  endpoint process and remote-execution telemetry, and internal flow logs.
  Anchor on the account and the source host and expand outward.

## Investigation steps

Collect all four signals; the verdict is derived from them at the end.

### 1. Source and entry reconstruction — signal A

Establish where the movement originated and how the actor got onto the
source host. **Signal A fires** when the source host itself has an open or
recent compromise signal — an earlier flagged sign-in, a beacon, a
malware detection — tying the movement to a known foothold rather than a
standalone admin action.

### 2. Credential attribution — signal B

Identify the credential used to authenticate to the destination and how it
was obtained. **Signal B fires** on stolen-credential shapes: pass-the-hash
or pass-the-ticket (logon type / ticket anomalies), a service or admin
account used from a host it never runs on, or a credential that appeared on
the source host through dumping rather than interactive logon. Note the
privilege level — movement escalating toward domain admin weighs heavily.

### 3. Technique and path scoping — signal C

Map every hop: from the source, enumerate all destinations reached with the
same credential or technique in the window, then repeat from each reached
host. **Signal C fires** when the path fans out across multiple hosts, uses
living-off-the-land remote execution (PsExec-style service creation,
WMI/WinRM, scheduled tasks) inconsistent with normal administration, and
reaches assets the account has no operational reason to touch.

### 4. Objective and impact — signal D

On the reached hosts, look for what the movement was *for*: credential
dumping, data staging, backup/shadow-copy tampering, new persistence, or
sensitive-system access. **Signal D fires** when the path terminates in
actions on objective — this confirms an intrusion over a misread admin task
and sets the real blast radius.

## Verdict rule

- **malicious:** signal B or C plus A or D — stolen-credential or
  fan-out movement tied to a foothold or ending in actions on objective.
  Movement reaching a domain controller or backup infrastructure with
  stolen credentials is malicious on its own.
- **suspicious:** an anomalous hop (C) with an unusual credential where the
  source foothold and objective can't be established but a sanctioned admin
  explanation can't be shown either.
- **inconclusive:** the path can't be reconstructed because authentication
  or endpoint logs for the hosts are missing.
- **benign:** the movement resolves to sanctioned administration — a
  jump-host, a patch/config tool, or an admin whose account, source, and
  targets positively match their documented role and baseline — with no
  foothold, no stolen-credential shape, and no actions on objective.

## Output

### Verdict
One of `malicious` / `suspicious` / `inconclusive` / `benign`, with the
signals that decided it.

### Recommended actions
When not benign: isolate the source and every reached host, disable and
rotate the credential used (and any credentials exposed on the path),
revoke active sessions/tickets, preserve artifacts on the path for
forensics, and hunt for the same credential and technique beyond the mapped
hosts. Prioritize any domain-privileged or backup systems in the path.

### Evidence
The reconstructed path (source → each hop with timestamps), the credential
used and how it was obtained, the technique per hop, the full list of
reached assets, the source host's foothold status, and any actions on
objective found.

### Reasoning
Name the signals and how they stacked — a beaconing workstation using a
pass-the-hash admin credential to reach a file server and then a domain
controller, dumping credentials on the way, is malicious; a backup service
account touching its usual set of servers from the known backup host is
benign.
