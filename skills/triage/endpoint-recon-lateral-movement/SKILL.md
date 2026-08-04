---
name: Endpoint Recon Lateral Movement
description: Triage a host alert where the environment is being mapped or the
  actor is moving between hosts — system, account, and network discovery
  commands run on the host, and remote execution or remote-session pivots to
  other machines. Reads the actor and host role against the breadth of discovery
  or the destination of a pivot to tell sanctioned scanning and admin paths
  apart from an attacker fanning out, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - discovery
    - lateral-movement
    - enumeration
    - remote-execution
---

# Triage Steps

This class fires on commands that admins, inventory tools, and ordinary tooling run constantly — a single discovery command or one remote session is low-conviction noise on its own. What makes it a signal is breadth and authority: many distinct discovery techniques from one host in a short window, or a pivot reaching a destination the actor has no documented reason to touch. The thing to read is the actor and host role against what they are doing — an inventory scanner on a management host enumerating the fleet is its job, while a standard workstation running account, network, and security-product discovery back-to-back is mapping. Triage here is reading that mismatch and deciding whether this is expected admin work or someone getting their bearings and fanning out.

Start from this detection's track record on this actor and host — a scanner that sweeps nightly and always closes benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and one strong lead (a burst of distinct discovery from a user workstation, a non-admin authenticating to a domain controller) can carry the call. When this co-fires with a credential-theft or persistence alert on the same host, fold this alert into that higher-priority triage rather than triaging it independently; credential-based lateral movement — the same credential appearing on multiple targets — is a call the credential-theft skill owns.

**Leads that point to a real threat** — what to look for in the data:

- **A burst of distinct discovery techniques.** Several different categories run in a short window from the same process tree — account enumeration, network topology, process or security-product discovery, credential-store location: `net user /domain`, `net group "Domain Admins"`, `nltest /dclist`, `whoami /all`, `tasklist /svc` in quick succession. Breadth and density, not any single command, are the tell.
- **Directory enumeration at scale.** Programmatic LDAP queries pulling users, groups, or computers wholesale, or queries for high-value targets and trust relationships — the shape of mapping a directory rather than looking up one record.
- **Pivot to a sensitive or unusual destination.** A non-admin authenticating to many hosts, or any account reaching a domain controller, backup server, or other sensitive target it has no documented reason to reach: `\\host\ADMIN$` writes, a remote-service install, WMI or WinRM remote execution to a server outside the actor's normal scope. An actor the identity directory already flags (risky-users) adds weight.
- **Recognized remote-execution toolmarks reaching an unexpected target.** Characteristic named objects, a service-install signature, or tool-specific process-name patterns left by remote-exec tooling, landing on a destination outside the actor's documented, recurring management pattern — these escalate regardless of the account. A toolmark on a host pair already on record as routine, recurring management is a mechanism-creation question, not a movement one.
- **Authentication-based movement with no tool.** The same account authenticating to an unusual number of targets in a short window, or credential material appearing where it should not — a hash or token presented in a context where only an interactive logon belongs (pass-the-hash). Cross-reference credential-theft alerts on the originating host; if one is present, defer to that skill and treat this as supporting context.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor and host role explain it.** A confirmed admin or a recognized management service running from a known scanner or jump host — the asset inventory (Axonius, managed-devices) confirms the host's role — following a recognizable admin path.
- **It matches the host's baseline.** The same discovery shape, or the same jump-host-to-target session, has run here before as normal activity.
- **Expected destination within baseline.** A single session from a jump host to a server the actor routinely manages, reaching a target it has a documented reason to touch.
- **Fleet-wide, not single-target.** The identical discovery command sweeps the environment on an inventory cadence — the shape of a scanner, which queries broadly; an intruder's recon comes from one foothold.
- **Clean history, no new scope.** This rule has closed benign on this actor before, with no new destination, no new technique, and no widened scope this time.

To confirm a lead instead of guessing, pull the thread: did the discovery burst precede a connection attempt, a download, or a privilege change, and did the pivot land on a host the actor never reaches? Corroboration turns scattered commands into a confirmed fan-out.

# Output

## Decision
- **escalate:** a burst of distinct discovery techniques, directory enumeration at scale, a pivot to a sensitive or unusual destination, recognized remote-execution toolmarks, or authentication-based movement to an unusual number of targets — especially when recon precedes a download, connection, or privilege change.
- **dismiss:** a confirmed admin or recognized scanner on a known management or jump host, a baseline match, or a single expected session within baseline explains it, with no new destination or widened scope. A dismiss is a positive call that the activity is benign, made with that context in hand — a scanner's management-host role you verified, a repeated discovery shape you recognized; an actor you couldn't confirm or a baseline you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the actor is a non-admin, the breadth is unusual, the destination is sensitive, or you're unsure, escalate.

## Evidence
The actor and host role (admin or scanner vs standard user or workstation), whether discovery is a single command or a burst of distinct techniques in a short window, whether a pivot's destination is expected or sensitive, the presence of recognized offensive toolmarks, and what preceded or followed in the same window.

## Reasoning
Name the leads that decided it and how they stacked — for discovery, a workstation running several distinct enumeration techniques in minutes is escalate while one lookup is noise; for movement, a non-admin reaching a domain controller is escalate while an admin's routine jump-host session is dismiss.
