---
name: Admin Role Duty Noise
description: Tune a detection that a named person keeps firing because the
  flagged action is their documented job — the Okta administrator provisioning
  the apps an app-creation rule flags, the IAM admin rotating the keys a
  credential rule watches, the helpdesk engineer resetting the passwords a reset
  rule counts. The most guarded exclusion class — a person can be phished,
  hijacked, or turn — so the exclusion stands only on a role that structurally
  explains the activity, is pinned to the duty pattern rather than the bare
  name, and leaves the same person outside that pattern still alerting.
type: tuning
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - exclusion
    - admin-role
    - privileged-user
    - false-positive
    - noise-reduction
---

# Tuning Methodology

This use case fires on detections watching a privileged action that, for one named person, is simply the job: the Okta admin whose role is provisioning applications tripping the new-app rule on every rollout, the IAM administrator rotating access keys under a credential-change rule, the helpdesk engineer whose queue is the password-reset detection's entire output. The signal is real and the rule is right to watch it — it is just watching the one person the org appointed to do it.

Excluding a person is the most dangerous tuning there is, so this class carries the heaviest burden of proof. "Benign this time" is not "benign always" — a legitimate user can be phished, have a session stolen, or act against the company tomorrow, and a clause that excludes their account hands an attacker a permanent blind spot exactly where the detection was watching. An exclusion is justified only when the activity is benign for a structural reason that holds regardless of intent: the person holds the role that grants and explains exactly this action, and the directory confirms it — an administrator performing the admin action the detection flags — or they are so dominant a share of an otherwise-benign signal that the detection is mostly noise because of them. Verify the role assignment in the identity directory; never take the job from the account name.

Establish durability by querying: how much of the detection's recent firing does this person's duty activity explain, and does it recur across the window as the same kind of action? Then read the detection's intent — this is where this class most often ends in a decline. Detections built to watch privileged users themselves — privilege misuse, insider movement, per-employee mass download — exist precisely because the admin is the risk; there, the high-volume admin is not noise to remove but the very thing the detection surfaces, and the answer is no tuning, however routine this case looked. Tune only on people who appeared in the triggering incident, and check the current logic first — an account already excluded is already tuned.

Pin the exclusion to the duty, not the bare name. The clause is appended to the detection as a filter and is never negated for you: it must exclude the benign by NOT matching it — a bare match (`==`, `contains`) keeps only this person's events and silently disables the detection. Prefer the durable signal that carries the duty over the individual: the admin role field, the management console the work always comes from, the source the person always operates from — `not(actor.user.name == "ayo.oriola" and src_endpoint.ip == <the admin console egress>)` rather than `actor.user.name != "ayo.oriola"`, and a role-based clause over a name-based one whenever the events carry the role. Read the field paths off the actual triggering events. Then adversary-test it: if this account were phished tomorrow, would the filter hide the takeover? The exclusion must leave the same person acting outside the duty pattern — new source, new hours, actions beyond the role — and anyone else performing the action, still alerting.

# Output

## Action
**exclude** — one filter clause appended to the detection removing the role-holder's documented duty activity; when the role does not structurally explain the action, the directory does not confirm it, or the detection watches privileged users by design, propose nothing — declining is the expected outcome for most person-exclusion requests.

## Target
The detection whose false positive was confirmed — one appended filter clause on a field present in its current logic.

## Value
The clause, one line: the person pinned to the duty pattern — `not(<actor> == <name> and <duty signal> == <its value>)` on the role field, console, or source that carries the job — never the bare account name alone, never a bare match operator.

## Evidence
The identity directory entry confirming the role that grants and explains the action; the triggering events the field paths were read from; aggregation counts showing the share of recent firing this person's duty activity explains and its recurrence; the detection's current logic and existing tuning suggestions.

## Reasoning
The mechanism, not the measurements: this person holds the role whose documented job is exactly this action, so the rule is flagging appointed work — and what still alerts: the same action by anyone else, and this same account acting outside the duty pattern it was pinned to.
