---
name: Application CICD Pipeline Abuse
description: A build pipeline running something new - a workflow file
  changed and triggered minutes later with no review between, push
  protection bypassed on the repository that just gained it, a CI bot token
  minting repositories, a self-hosted runner re-homed. Reads the change path
  and the review trail.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  mitre:
    - T1648      # Serverless Execution
    - T1059      # Command and Scripting Interpreter
    - T1195.002  # Compromise Software Supply Chain
    - T1078.004  # Cloud Accounts
  labels:
    - application
    - cicd
    - pipeline-execution
    - build-automation
    - execution
    - initial-access
---

# Triage Steps

Build systems change all day. Workflow files get edited, jobs get created, runners come and go, and every merge triggers something, so the fact that a pipeline ran is not the signal. The signal is whether the repository's approved change path put that automation there and whether the identity behind the run is the one that always does this. A pipeline is a standing execution engine with credentials of its own, so whoever can edit what it runs gets execution as the build system without ever touching a host.

Start from this detection's track record on this actor and repository - a release bot that publishes on every tag and is always closed benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (a workflow token minting repositories, a workflow edited and triggered with no review in between) can carry the call. This class turns on whether the pipeline executed through an approved change path with its expected identity, distinct from whether a governance toggle was flipped by the right actor, which is application-control-policy-tampering's and stops at the flip, and from whether content reached an untrusted destination, which is application-data-exfiltration-oversharing's. Extending an AI agent's capability from an untrusted source is application-ai-tooling-supply-chain's, not a build system's execution path.

**Leads that point to a real threat** - what to look for in the data:

- **Automation written and run in one breath.** A workflow file under `.github/workflows/`, a job, or a notebook created or changed and then triggered in the same window, with nothing in between: a push straight to the default branch, a protected-branch override, or a merge the author approved themselves. The review trail is what normally sits between those two events, and here it is missing.
- **A guardrail bypassed on the same commit or repository.** A push-protection bypass, secret scanning switched off, or a required-review override on the very repository that just gained new automation. One actor removing the check and then adding the thing the check exists to catch is a sequence, not two unrelated admin edits.
- **The pipeline's own identity doing what it never does.** The workflow token or CI bot publishing a release, creating repositories, or writing to a repository outside the one it builds. Read the bot's own history, not its permissions: a token whose whole life is one repetitive job, suddenly minting resources, has no mandate for that even when the scope allows it.
- **A runner nobody owns.** A self-hosted runner registered, moved between runner groups, or attached to a public repository by an actor who does not own the CI infrastructure. A runner reachable from a public repository will execute whatever a fork's pull request brings to it, on a machine inside the network.
- **A build identity with no history behind it.** A Databricks job, cluster, or notebook created and run by an identity that has no job history in the audit trail, or a job whose notebook was changed right before the run - the same edit-then-trigger shape playing out on the data platform.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A reviewed pull request, and this run is its first build.** The change arrived through a pull request approved by a code owner who is not the author, and the run's commit is that merge. The audit trail carries all three in order: the review, the merge, the run.
- **The repository's documented release or dependency automation.** The dependency bot or the release bot, on the repositories it always touches, at the cadence it always runs, doing the one action it exists to do. Same identity, same repositories, same shape as its prior window.
- **A change-recorded infrastructure window.** A runner or org-level CI change made by the infrastructure owner inside a documented migration window, with the same change landing across the other repositories or runner groups in that window rather than on one.
- **A new repository's own scaffold.** The repository was created minutes earlier by this same actor, and this is the template workflow's first run - creation and first run by the creator, with nothing else in the repository touched. Stolen-token abuse wears this same shape, so all three have to hold: the actor has created repositories before in this org, the workflow matches the org's own template set rather than one the actor wrote themselves, and the run reached nothing privileged - no org secrets read, no self-hosted runner. Any one of the three missing and this is not the lead.

To confirm a lead instead of guessing, pull the thread: did the run reach past its own repository - a release published, a repository created, a secret read - and does the acting identity have any prior job or release history at all?

# Output

## Decision
- **escalate:** automation created or changed and then triggered with no review trail, a guardrail bypassed on the repository that just gained it, the pipeline's own token publishing releases or minting repositories, a runner registered or re-homed by an actor who does not own CI, or a job run by an identity with no job history - especially two of these on the same repository in the same window.
- **dismiss:** a code-owner-reviewed merge whose first build this is, the repository's documented release or dependency automation at its normal cadence, a change-recorded infrastructure window, or a new repository's scaffold run by a creator who has made repositories before, from the org's own template, reaching no secret or self-hosted runner. A dismiss is a positive call that the pipeline ran through its approved path, made with that context in hand - a review you found in the audit trail, an automation identity whose history you actually read; a change path you couldn't trace or an identity you couldn't place is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure - or the same actor both removed a guardrail and added the automation - escalate.

## Evidence
The acting identity and its type (human, workflow token, release or dependency bot, infrastructure owner), the change path it used (reviewed pull request, direct push to the default branch, protected-branch override, self-approved merge), the gap between the automation changing and running, any guardrail bypass on the same commit or repository, the runner's owner and whether it is attached to a public repository, the identity's prior job and release history, and how wide the change went.

## Reasoning
Name the leads that decided it and how they stacked - a workflow pushed straight to the default branch and triggered two minutes later by the actor who also bypassed push protection on that repository is escalate on its own; the release bot publishing a tagged release on the repository it always builds is dismiss.
