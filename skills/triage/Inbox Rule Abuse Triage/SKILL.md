---
name: Inbox Rule Abuse Triage
description: Triage an alert where a mailbox rule was created or changed in a way
  that hides mail — auto-forwarding to an external address, or moving and marking
  read anything matching finance, security, or password keywords. Reads the audit
  trail and the rule definition to tell an organizing user or a helpdesk fix apart
  from a rule planted to intercept replies or bury alerts after a mailbox takeover,
  and decides escalate or dismiss.
type: triage
version: 1.1.0
metadata:
  author: logsmith
  labels:
    - email
    - identity
    - account-takeover
    - persistence
    - bec
---

# Triage Steps

This class fires on a mailbox rule change — a new or edited rule in Exchange
Online, Google Workspace, or another mail platform. Most rule changes are
housekeeping: people file newsletters into folders, forward their mail to a
personal account before a holiday, mark a mailing list as read. A rule is also
one of the quietest footholds an attacker keeps after a mailbox takeover, because
it survives a password reset and needs no further sign-in: it silently forwards
replies to a hijacked thread, or deletes the security notifications that would
give the intrusion away. The signal is not that a rule changed — it is what the
rule *does* and whether the account it changed on is otherwise clean.

Begin with the state of the mailbox's owner: a rule created minutes after a
sign-in that triage already flagged, or on an account with an open takeover
alert, starts the call near escalate. Then read the rule definition and the
audit event for the leads below. They stack; a single strong one — forwarding
to an external address the user never mailed, or a rule that deletes anything
saying "security alert" — can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Forwarding out of the org.** A rule that forwards or redirects mail to an
  external, personal, or newly-registered domain — the classic reply-interception
  and data-siphon shape. In the audit log: a `New-InboxRule` / `Set-InboxRule`
  (or the Google equivalent) with `ForwardTo`, `RedirectTo`, or a forwarding SMTP
  address outside the tenant. It weighs most when the destination is a domain the
  user has no mail history with, or when org-wide auto-forwarding is supposed to
  be disabled and this rule is an exception.
- **A rule that hides, not organizes.** A rule keyed on words an attacker wants
  the user not to see — `invoice`, `payment`, `wire`, `password`, `security alert`,
  `sign-in`, `MFA`, the attacker's own display name — that moves matches to
  `Deleted Items`, `RSS`, `Archive`, or `Conversation History` and marks them read.
  Deleting or hiding is the tell; foldering into a clearly-named folder the user
  reads is not.
- **Created in a takeover window.** The rule change lands in the same session or
  hour as a sign-in that triage flagged, an MFA registration the user never
  started, or a token replay — persistence set immediately after access. The rule
  and the suspicious login sharing a source IP or client is the strong version.
- **Set by someone other than the owner.** The audit event shows the rule created
  by a different principal, a delegate, or an OAuth app rather than the mailbox
  owner — especially an app with mail-write scope the user doesn't recognize.

**Leads that rule it out** — benign context you can actually see in the data; if
the data doesn't show it, you don't have it:

- **It organizes, and stays inside.** The rule files matches into a named folder
  the user opens, or forwards to another internal mailbox for a shared workflow —
  no external destination, no delete, no mark-as-read on security mail.
- **It fits the owner and the moment.** The rule was created by the mailbox owner
  from a device, network, and session that positively match their baseline, with
  no takeover signal anywhere near it — an out-of-office forward to a teammate, a
  filter for a project alias.
- **A helpdesk or admin change on record.** The change traces to a documented
  migration, a delegation the user requested, or an admin acting on a ticket.
- **A known automation.** A mail-integration app the tenant sanctioned, creating
  the rule on its normal schedule with scopes the org approved.

To confirm a lead instead of guessing, pull the thread: after the rule appeared,
did mail matching it actually get forwarded or deleted, and did the same session
touch a sign-in, an MFA registration, or a file download? A rule plus activity in
the same window is a confirmed foothold, not a suspicion.

# Output

## Decision
- **escalate:** a rule that forwards or redirects to an external or unfamiliar
  destination, or that deletes/hides mail matching finance or security keywords —
  especially one created in the same window as a flagged sign-in or MFA change, or
  set by a principal other than the owner. Any rule paired with a takeover signal
  on the same account escalates on its own.
- **dismiss:** a rule that files mail into a folder the user reads or forwards
  internally for a known workflow, created by the owner from a session that matches
  their baseline with no takeover signal near it, or a change traced to a documented
  helpdesk or admin action. A dismiss is a positive call that the rule is benign,
  made with the rule definition and the owner's context in hand — not the mere
  absence of a forward. When the destination, the intent of the rule, or the
  owner's context is unclear, escalate.

## Evidence
The rule definition (conditions, actions, destination address), the audit event
and who created it, the mailbox owner's takeover status and sign-in baseline around
the change, whether matching mail was actually forwarded or deleted, and any
sign-in, MFA, or OAuth activity sharing the session.

## Reasoning
Name the leads that decided it and how they stacked — a rule forwarding invoices
to a personal domain, created minutes after a sign-in from a new ASN, is escalate
on its own; an owner-created filter moving a newsletter to a named folder from
their usual device is dismiss.
