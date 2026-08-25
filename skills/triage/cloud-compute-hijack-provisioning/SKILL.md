---
name: Cloud Compute Hijack Provisioning
description: Compute provisioned in bulk, or a running workload talking to a
  mining pool - launch bursts fanning across regions, a GPU family the
  account has never run, Stratum egress from a workload address. Reads the
  launching identity, family and region against the account's history, and
  where egress goes.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - cryptomining
    - compute-provisioning
    - resource-hijacking
    - impact
    - execution
  mitre:
    - T1496.001  # Compute Hijacking
    - T1578.002  # Create Cloud Instance
---

# Triage Steps

Cloud accounts launch and tear down compute all day, and they fail at it constantly - queues scale, spot capacity runs out, a region says no. So the fact that instances were launched, or that launches failed, is not the signal. The signal is whether the shape of the provisioning matches work this account already does: which identity launched, which instance family and region, whether anything ties the new capacity to a named workload, and where that workload's traffic goes once it boots. There is no cost or billing telemetry here, so a spend curve is not one of your leads - launch shape, region, actor, and pool egress are what you have.

Start from this detection's track record on this identity and account - a rule that fires whenever the training pipeline scales its GPU queue and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (Stratum egress from a workload's own address, a GPU family and region the account has never run) can carry the call. This class turns on the quantity of compute provisioned and what the workload then talks to, distinct from the content a workload is made to run - a function's code replaced, an instance's user-data rewritten - which is cloud-workload-code-execution's, and distinct from the same objective on a managed inference API, which is application-ai-service-hijack's.

**Leads that point to a real threat** - what to look for in the data:

- **A launch burst fanning across regions from one identity.** `RunInstances` and its GCP and Azure equivalents repeating within seconds, or a wall of `AccessDenied` / `UnauthorizedOperation` on those same calls, spread across regions this identity does not work in. Attackers try every region because they do not know where the account has quota; a pipeline launches where its data already lives. Read the error code on the failures - an authorization denial repeated region by region is a probe, not a capacity problem.
- **An instance family or region with no history here.** Large or accelerated families - the p, g, and inf classes, their GCP A2/G2 and Azure NC/ND counterparts - or any region where the account has never run compute. The account's own launch history over the window is the baseline; a family that appears for the first time, in bulk, is the shape of someone buying mining capacity on your card.
- **A launcher with nothing tying it to a workload.** The identity that launched has never called a launch API before, or the new instances carry no owner, cost-center, or environment tags, no launch template, no scaling group, and no match in the asset inventory. Capacity that belongs to a real team is named and owned somewhere; capacity that belongs to nobody was not provisioned for the account's benefit.
- **A quota increase requested just before the launches.** A service-quota or vCPU limit increase - `RequestServiceQuotaIncrease`, a GCP quota bump, an Azure vCPU quota request - minutes or hours before the burst, from the same identity, with no ticket or rollout behind it. Raising the ceiling and then filling it is one action in two calls.
- **Mining-pool or Stratum egress from a workload address.** Outbound from the cloud workload's own address to a known pool host, or to a Stratum port (3333, 4444, 5555, 14444, 45700), or a pool domain resolved shortly after boot. Reputation on that destination decides it. This lead can carry the escalate alone - it says the compute is already being consumed by someone else, whatever the provisioning looked like.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The pipeline's own launch shape.** The batch, training, or render identity launching its usual family in its usual region, with the audit rows naming an existing queue, scaling group, or launch template behind the launches. All three parts are checkable in the row: the identity, the family and region against its history, and the requester the launch came through - a scaling group filling itself is a different event from a principal calling `RunInstances` by hand.
- **Capacity or spot-interruption retries, not authorization denials.** The repeated failures carry capacity codes - `InsufficientInstanceCapacity`, `SpotMaxPriceTooLow`, a spot interruption, `ZONE_RESOURCE_POOL_EXHAUSTED` - and walk availability zones inside one region rather than jumping between regions. Retry loops on capacity are how schedulers behave; the error code is what separates them from a permission probe, so read it before you count the attempts.
- **A named team's onboarding or load test with an approved quota ticket.** A quota-increase request or change record that names the team, covers this window, and covers this instance family, with the launches staying inside what the ticket asked for. A quota bump you can see with no ticket behind it is the escalate lead above, not this one.
- **The account's own GPU churn baseline.** A research or ML account whose history across the window already shows launches at this shape and rate - same families, same regions, the same launch-and-terminate rhythm - so today's burst is one more turn of a wheel already spinning. The baseline has to show this shape, not merely show that the account uses GPUs.

To confirm a lead instead of guessing, pull the thread: does this identity's own history contain launches of this family in this region, and after boot did the new instances talk to the account's own services or to an outside pool?

# Output

## Decision
- **escalate:** mining-pool or Stratum egress from a workload address, a launch or authorization-failure burst fanning across regions from one identity, a first-time large or GPU family or region, compute with no tag, template, or inventory owner behind it, or a quota increase followed straight away by the launches it enabled - especially two of these together.
- **dismiss:** the batch, training, or render pipeline launched its usual family in its usual region under an existing queue or scaling group, the failures are capacity or spot retries by their error codes, an approved quota ticket covers the window and the family, or the account's own baseline already shows this launch shape and rate. A dismiss is a positive call that the provisioning is benign, made with that context in hand - a pipeline identity and launch template you confirmed, capacity error codes you actually read, a ticket or baseline you matched; a launcher you couldn't place or capacity you couldn't tie to a workload is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the egress destination is a pool, the launching identity has no history, or you're unsure, escalate.

## Evidence
The launching identity and whether it is a known batch, training, or render pipeline; the instance family, size, and region against that identity's and the account's own history; the count of launches and of failures, with the failure error codes; whether a launch template, scaling group, queue, or owner tag stands behind the capacity; any quota or limit increase in the window and the ticket behind it; and the destination, port, and reputation of the workload's outbound traffic.

## Reasoning
Name the leads that decided it and how they stacked - a workload address reaching a Stratum port minutes after a first-ever GPU launch in a region the account never uses is escalate on its own, while the training role launching its usual family under its own scaling group, with the failures all reading as spot interruptions, is dismiss.
