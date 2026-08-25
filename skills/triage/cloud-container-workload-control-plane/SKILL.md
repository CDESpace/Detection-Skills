---
name: Cloud Container Workload Control Plane
description: A Kubernetes object that runs code or hands over the node - a
  privileged pod mounting the host root or the container socket, exec into a
  running pod, an admission webhook registered or bypassed. Reads the
  requesting identity, whether a controller stands behind it, and the
  namespace's deploys.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - kubernetes
    - admission-control
    - container-boundary
    - execution
    - privilege-escalation
    - persistence
  mitre:
    - T1611      # Escape to Host
    - T1609      # Container Administration Command
    - T1053.007  # Container Orchestration Job
    - T1552.007  # Container API
    - T1553.006  # Code Signing Policy Modification
---

# Triage Steps

Clusters change every minute: controllers reconcile, GitOps applies, CI deploys, and CSI, CNI, and logging DaemonSets land on every node with exactly the host mounts they were built to need. So a privileged pod, an exec, a Job, or a Secret read is not the signal by itself - all four are somebody's normal Tuesday. The signal is provenance: which identity asked, whether an owning controller stands above the object, and whether that namespace's own history already contains this spec shape. Read the requester and the owner reference in the audit row, not the object's name.

Start from this detection's track record on this cluster and service account - a rule that fires on every DaemonSet rollout and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (a human credential creating a hostPath pod that mounts the host root, an admission webhook registered by an identity that owns no workloads) can carry the call. This class turns on the in-cluster object and the admission decision as cluster audit and pod logs show them, and it never claims a process escaped at runtime - there is no syscall telemetry here, so a spec that hands over the node is judged on the spec. Where the object is a provider compute surface instead - a function's code, a task definition, instance user-data, a run-command - that is cloud-workload-code-execution's; RBAC grants that hand out the power are cloud-iam-privilege-persistence's, and the breadth of reads against a cloud secret store is cloud-recon-secret-harvest's.

**Leads that point to a real threat** - what to look for in the data:

- **A boundary-breaking spec from a principal that is not a controller.** `securityContext.privileged: true`, `hostPID`, `hostIPC`, `hostNetwork`, or a `hostPath` volume on `/`, `/etc`, `/var/run/docker.sock`, or `/var/lib/kubelet` - requested by a human `user.username`, an unknown token, or a service account with no workload mandate in that namespace. A pod that mounts the host root or the container socket already holds the node; nothing further has to happen for this to matter.
- **Exec or attach on a human credential, or a pod with no owner.** A create on the `pods/exec`, `pods/attach`, or `pods/portforward` subresource by a person's credential rather than a controller, or a bare pod whose `metadata.ownerReferences` is empty - nothing in the cluster asked for that pod, someone typed it. Deployments come from ReplicaSets; a naked pod is a hand on the API.
- **A Job or CronJob with no manifest behind it.** A Job, CronJob, or Deployment created by an identity with no workload history in that namespace, or with no matching manifest in the deploying repository - and worse when its `command` or `args` is a shell (`/bin/sh -c`) or a fetch-and-run (a curl or wget piped into a shell, then chmod). Real workloads ship an entrypoint; a shell that pulls its payload at start is bringing code the cluster never reviewed.
- **Admission bent, bypassed, or an unfamiliar registry.** A `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration`, or an admission policy, registered, edited, or deleted; a break-glass pod admitted past policy; or the workload landing in `default` or a user namespace with an image from a registry this cluster has never pulled from. A webhook that rewrites every pod on the way in is a persistent hand on all future workloads.
- **Secrets pulled, recon alongside it, and then the pod ran.** `get` or `list` on `secrets` in a namespace by a workload identity not provisioned to hold them, or the same identity in the same audit window also running `SelfSubjectAccessReview` and `SelfSubjectRulesReview` and listing across namespaces - the mapping sequence offensive tooling produces - and then the pod actually started. The recon plus the successful start is the pair that matters; recon that ended in denials is a weaker story than recon followed by a running container.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **A cluster controller or operator owns the spec.** The requester is a CSI, CNI, monitoring, or logging DaemonSet service account - `system:serviceaccount:kube-system:...` and its kin - whose documented spec includes exactly this hostPath, and `ownerReferences` names the DaemonSet or ReplicaSet controller rather than a person. All three have to hold: the service account, the mount matching that addon's known-good spec, and the controller as owner. A privileged spec with a controller owner was reconciled; the same spec with a human requester was typed.
- **The namespace's GitOps or CI account applied its usual shape.** The requester is the Argo, Flux, or CI service account that owns that namespace; the object matches the previous revision of the same object - same image digest, same spec fields - and it arrived on that pipeline's usual cadence, which the namespace's own audit rows across the window show. The same account applying the same shape it applied yesterday is a deploy.
- **A managed control plane or provider system account on its own bookkeeping.** kube-system, service-linked, or provider system accounts doing node lifecycle work, the cluster autoscaler adding capacity, or a system-namespace addon pulling the cluster's own image during a cluster-version or node-group upgrade that the provider audit log records in the same window. The upgrade or scaling event has to be visible; "probably the autoscaler" is not this lead.
- **Secrets read by the namespace's own account, or a named admin inside a change window.** The reader is that namespace's own service account, or the external-secrets or CSI secrets-store driver on its fixed interval - identical calls at an even period across the window - or a named platform admin acting inside a change window, with the workload torn down when the window closes and the delete visible in the audit rows.

To confirm a lead instead of guessing, pull the thread: does the object carry an owner reference to a controller, and has this requester applied this same spec in this namespace before? Where pod logs exist, do they show the container doing its documented job or starting a shell?

# Output

## Decision
- **escalate:** a boundary-breaking spec (privileged, hostPID, hostNetwork, or a hostPath on the host root, /etc, the container socket, or the kubelet path) from a principal that is not a system controller, GitOps, or CI; exec, attach, or a bare owner-less pod on a human credential; a Job or CronJob with no manifest or a shell-and-fetch command; an admission webhook registered, edited, or bypassed; an image from a registry this cluster never pulls; or namespace Secrets read by an identity not provisioned to hold them, especially with recon in the same window and the pod running.
- **dismiss:** a cluster controller or provider system account owns the spec and the owner reference proves it, the namespace's GitOps or CI account applied the shape it applies every deploy, a recorded cluster or node-group upgrade explains the addon, or the Secret read belongs to that namespace's own account or driver on its fixed interval. A dismiss is a positive call that the in-cluster change is benign, made with that context in hand - a controller owner reference you read, a prior revision of the same object you matched, an upgrade event you found; a requester you couldn't place or a spec you couldn't match to a prior revision is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the requester is human or unknown, the spec breaks the pod boundary, or you're unsure, escalate.

## Evidence
The requesting identity from the audit row and whether it is a system controller, GitOps or CI account, provider system account, or a person; the object kind, namespace, and its owner references; the specific boundary fields in the spec - privileged, hostPID, hostIPC, hostNetwork, and each hostPath - and the image and its registry; the verb and subresource for exec, attach, and Secret access; the namespace's prior revisions and deploy cadence for the same object; any recorded cluster-version or node-group upgrade in the window; and what pod logs show the container doing after it started.

## Reasoning
Name the leads that decided it and how they stacked - a named user creating an owner-less pod that hostPath-mounts the container socket into a user namespace, minutes after that same identity listed Secrets across namespaces, is escalate on its own, while the logging DaemonSet's service account creating its documented `/var/log` hostPath pod with the DaemonSet controller as owner is dismiss.
