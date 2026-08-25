---
name: Cloud Network Perimeter Exposure
description: A cloud rule change that opens an inbound path from the
  internet - 0.0.0.0/0 added to 22, 3389, or 3306, a rule deleted rather
  than narrowed, peering toward an unfamiliar network, a public IP on a
  private-subnet resource. Reads the editing identity, the source scope, and
  what arrived after.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - network-exposure
    - security-group
    - firewall-rule
    - defense-impairment
    - initial-access
  mitre:
    - T1686  # Disable or Modify System Firewall
    - T1578  # Modify Cloud Compute Infrastructure
---

# Triage Steps

Perimeter rules change all day in a live account: pipelines re-apply their rule sets, ingress controllers manage the rules for the services they create, an admin opens a port for a migration and closes it again by lunch. So a security-group or NSG edit is not the signal. The signal is direction and scope - did this change add an inbound path from somewhere untrusted to something worth reaching, and does the pipeline or change record that owns the perimeter explain it? The flow logs on both sides of the change (VPC-Flow-Logs, NSG-Flow-Logs) and the firewall's own logs tell you the part the control plane cannot: whether anything came through the opening.

Start from this detection's track record on this identity and this network - a rule that fires whenever the network pipeline re-applies its rule set and always closes benign starts the call near dismiss - then read the leads below. None is required on its own; they stack, and a single strong one (0.0.0.0/0 on 3389 with an accepted external connection right after it) can carry the call. This class turns on an inbound path opened to a cloud compute or management surface in the provider's control plane, distinct from the same act on one machine's own host firewall, which is judged on that host. Blinding the account so nothing is recorded stays with cloud-security-control-evasion, and a storage bucket policy or a snapshot made public remains cloud-data-exfiltration-destruction's - the object here is a network path, not a record and not a data store.

**Leads that point to a real threat** - what to look for in the data:

- **Any-source ingress on a management or database port.** `AuthorizeSecurityGroupIngress`, an NSG security rule, or a GCP firewall rule adding 0.0.0.0/0 or ::/0 to 22, 3389, 1433, 3306, 5432, or 6379. These ports are the ones an actor wants and the ones no service needs open to the whole internet; the port list plus the any-source scope is the whole lead, and it gets worse when the target sits in front of a database or a jump host.
- **A rule deleted, or allow-any added, rather than a scoped rule replaced.** A firewall or NSG rule removed outright with nothing narrower put back, or a new rule with protocol any, port any, source any. Direction is what separates administration from clearing a path: a replacement keeps parity or tightens, a deletion can only open. Check whether a matching create follows the delete in the same window before reading it as a replacement.
- **A new path toward a network nobody recognizes.** A VPN gateway, VNet or VPC peering, or transit-gateway attachment created toward a peer account, subscription, or on-prem CIDR that appears nowhere else in the account's topology. Peering is not a port - it is a whole network reaching yours - so an unfamiliar peer on the far end matters more than the ports it carries.
- **Public reachability attached to something that lives private.** An Elastic or public IP associated with an instance, a public-IP configuration added to a NIC, or serial-console access enabled - `EnableSerialConsoleAccess` and its provider equivalents - for a resource whose subnet has no internet route by design. The resource's own placement is the tell; a private-subnet workload gaining a public address was not deployed that way.
- **A first-time network editor, with traffic right behind the change.** The change comes from an identity with no history of network configuration calls - a user or compute role rather than the pipeline that owns the perimeter - and the flow logs show an accepted external connection to that port inside the window. The pairing is what makes this decisive: an unfamiliar editor is suspicious, an unfamiliar editor whose opening was immediately used is a foothold.

**Leads that rule it out** - benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The network IaC role's usual rule set.** The requester is the network pipeline's assumed role or service principal, and the same rule shape it applies in the other environments or regions is present in this window on its deploy cadence. The check is that the same rules exist elsewhere in the account, not that the tool has an infrastructure-sounding name.
- **A scoped, named CIDR inside a change window.** The allow's source is a named corporate, VPN, or office CIDR the account's other rules already use - not 0.0.0.0/0, not a /8 wrapped around it - and a change window covers the timestamp. Scope comes first: a change ticket does not turn an any-source rule into a scoped one, and a scoped rule to a corporate range is the ordinary case even when the ticket is missing.
- **The principal that owns those rules managing them.** A load balancer, ingress controller, or the AKS or EKS cluster service principal editing rules on resources it created, matching the service objects it manages. The rule's target should be a resource that principal owns; a cluster identity editing a rule on an unrelated database subnet is not this lead.
- **Opened and closed inside one deploy, with nothing in between.** The same pipeline added the rule and removed it within the same deploy, and the flow logs show no external connection to that port between the two events. Both halves have to be visible - the close in the audit rows, and the quiet window in the flow logs.

To confirm a lead instead of guessing, pull the thread: do the flow logs show an external source reaching that port after the change, and does the same rule shape exist in the account's other environments?

# Output

## Decision
- **escalate:** 0.0.0.0/0 or ::/0 added to a management or database port, a rule deleted or an allow-any rule added rather than a scoped rule replaced, a VPN gateway, peering, or transit attachment toward an unfamiliar network, a public IP or serial-console access attached to a private-subnet resource, or a change from an identity with no network-configuration history - decisive when the flow logs show an external connection to that port right after.
- **dismiss:** the network IaC role applied the rule set it applies in the other environments on its deploy cadence, the allow is scoped to a named corporate or VPN CIDR inside a change window, the load-balancer or cluster principal is managing rules on resources it owns, or the pipeline opened and closed the rule inside one deploy with no external connection in between. A dismiss is a positive call that the perimeter change is benign, made with that context in hand - a pipeline identity and matching rule shape you found elsewhere in the account, a named CIDR and window you confirmed, a quiet flow-log window you actually checked; a source you couldn't scope or an editor you couldn't place is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the source is the whole internet, the rule was deleted rather than replaced, or you're unsure, escalate.

## Evidence
The identity that made the change and whether it has network-configuration history, the exact action (authorize, revoke, delete, create) and whether a narrower rule replaced it, the source CIDR and whether it is any-source or a named corporate range, the protocol and destination ports, the target resource and its subnet's internet routing, the peer account, subscription, or CIDR on a gateway or peering change, the same rule shape in the account's other environments, any change window or ticket covering the timestamp, and what the VPC or NSG flow logs and firewall logs show reaching that port after the change.

## Reasoning
Name the leads that decided it and how they stacked - a compute role adding 0.0.0.0/0 on 3389 to a private-subnet instance, with an accepted external connection in the flow logs 4 minutes later, is escalate on its own, while the network pipeline re-applying the same office-CIDR rule set it runs in every other region is dismiss.
