---
name: Cloud Workload Code Execution
description: A change to a serverless function or a virtual machine that
  makes it run new code - a function's code package replaced from the
  console, instance user-data rewritten, an image from a public registry,
  SendCommand aimed at instances the caller never manages. Reads the caller
  and the code's origin.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - code-provenance
    - serverless
    - run-command
    - execution
    - persistence
  mitre:
    - T1648      # Serverless Execution
    - T1651      # Cloud Administration Command
    - T1021.007  # Cloud Services
---

# Triage Steps

Deployment pipelines rewrite what runs in a cloud account constantly: a function's code lands a dozen times a week, launch templates get new user-data on every image roll, patch automation fires commands at whole fleets on a schedule. So a workload changing, or code running, is not the signal. The signal is provenance - did the pipeline that owns this workload make the change, or did a principal reach into the control plane by hand and put its own code where the account would run it? Read the caller and its user-agent, where the code or image came from, and whether a deployment event stands anywhere in the same window. There is no runtime process telemetry here, so the control-plane rows and whatever the workload's own logs show after it started are the evidence.

Start from this detection's track record on this workload and caller - a rule that fires on every pipeline deploy of the same function and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (a console user-agent replacing a function's code and invoking it once, with no deployment anywhere in the window) can carry the call. This class turns on code and workload provenance across the provider's compute surfaces - functions, task definitions, instance user-data, run-command and remote sessions. When the alert is about the in-cluster object or the admission decision itself - a pod spec, an exec, a CronJob, an admission webhook - that is cloud-container-workload-control-plane's; IAM writes and who ends up holding power are cloud-iam-privilege-persistence's, read-only sweeps and secret pulls cloud-recon-secret-harvest's, the terminal data action cloud-data-exfiltration-destruction's, the volume of compute provisioned and mining-pool egress cloud-compute-hijack-provisioning's, and the console-token half of the remote-services technique cloud-cross-boundary-delegation-use's.

**Leads that point to a real threat** - what to look for in the data:

- **A human hand on a pipeline-only workload.** A console `userAgent` - `console.amazonaws.com`, `AWSCloudConsole`, an Azure portal client - or a named IAM user calling `UpdateFunctionCode`, `UpdateFunctionConfiguration`, or `RegisterTaskDefinition` on a workload only the pipeline ever touches. Worse when function environment variables gain an outbound URL or a credential value: the code did not have to change for the function to start reporting somewhere new.
- **Foreign code provenance.** An image or package from outside the org's own registry or artifact store - a public registry tag, a raw download URL in a build or start step, a function layer or task-definition image the account has never pulled before. The registry and digest in the row are checkable; code the account did not build is code nobody reviewed.
- **Update then invoke, with no deployment in the window.** Function code replaced and invoked once immediately afterwards, or an instance's user-data rewritten - `ModifyInstanceAttribute` on user-data, a new launch-template version - and then a stop/start or a scale event that makes it run, with no deployment or pipeline event anywhere in the window. Pipelines deploy and let traffic arrive; a single invoke straight after a change is someone testing their own payload.
- **Run-command reach into instances the caller never manages.** `SendCommand`, `StartSession`, `SendSerialConsoleSSHPublicKey`, or an Azure `runCommand` or command invoke, aimed at production instances the caller has no operational history with. One ad-hoc document against one high-value target, outside any maintenance window, is the shape - fleet patching looks nothing like it.
- **A new schedule planted.** A scheduled task or an events rule with a compute target, added in a project or account the calling identity has never deployed into. Schedules are persistence with a delay: the code runs again later, after whoever planted it has stopped touching the account.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The pipeline made it, and a deployment sits in the window.** The caller is the CI/CD or IaC assumed-role session or the OIDC workload identity, with the SDK user-agent it always uses, carrying the same image digest or function version from the org's own registry, into the function, task definition, or launch template that pipeline owns - and the deployment event is visible in the same window. Caller, provenance, and target all have to line up; a pipeline-shaped role name on its own is not this lead.
- **Automation on its documented run.** Patch or configuration-management automation executing its own command document inside its maintenance window, or the launch-template and scaling-group pipeline rewriting user-data as part of its usual image roll. The document name, the window, and the fleet-wide target should all be visible in the rows - a broad target on a schedule is the tell that separates patching from a single-target command.
- **Cadence on record.** This function, task definition, or image appears in prior deployments at the same rhythm across the window - a rolling restart, a scheduled redeploy, the same digest going out again. Repetition with identical parameters and no human judgment between events is machine work, and a first-ever workload has no such history to show.
- **Break-glass session doing the task, with the workload behaving.** A remote session by on-call inside an incident window whose commands match that task, and the workload's own logs showing normal startup and request handling rather than a shell, a package install, or a new outbound destination. Both halves matter: the session's commands, and what the workload did after them.

To confirm a lead instead of guessing, pull the thread: is there a deployment or pipeline event behind this change in the same window, and did the workload's own logs afterwards show it doing its documented job or something new?

# Output

## Decision
- **escalate:** a console user-agent or named user changing a function, task, or workload only the pipeline touches, function environment variables gaining an outbound URL or a credential, an image or package from outside the org's registry, code or user-data replaced and then run with no deployment in the window, a run-command or remote session aimed at instances the caller has never managed, or a new schedule planted where that identity has never deployed.
- **dismiss:** the pipeline made the change with its usual SDK user-agent, the org's own registry digest, into the workload it owns, and the deployment event is in the window; or patch automation ran its own document inside its maintenance window; or the same function, task definition, or image shows the same deploy cadence across the window; or an on-call break-glass session's commands match the incident and the workload's logs show it doing its normal job. A dismiss is a positive call that the code change is benign, made with that context in hand - a pipeline caller and matching digest you confirmed, a maintenance window and document name you read, a prior deploy cadence you checked; a caller you couldn't tie to a pipeline or an image whose origin you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the change came from a console session, the code came from outside the org, or you're unsure, escalate.

## Evidence
The calling identity and its user-agent, and whether that caller is the pipeline that owns this workload; the exact action on the compute surface - function code or configuration, task definition, user-data, run-command, remote session, schedule; the image or package origin and digest against the org's own registry; any function environment variables added and whether they carry a URL or a credential; whether a deployment or pipeline event exists in the same window; the target instances, functions, or task definitions and the caller's operational history with them; the command document name and its maintenance window; the prior deploy cadence for this workload; and what the workload's own logs show after the change.

## Reasoning
Name the leads that decided it and how they stacked - a named IAM user replacing a function's code from the console, adding an outbound URL to its environment, then invoking it once with no deployment in the window, is escalate on its own, while the deploy role pushing the same registry digest into the function it owns, with the pipeline event alongside it, is dismiss.
