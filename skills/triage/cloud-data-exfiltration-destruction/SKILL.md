---
name: Cloud Data Exfiltration Destruction
description: Triage a cloud control-plane alert where an actor stages, copies
  out, or destroys data and resources — sharing or exporting snapshots, disks,
  or AMIs, downloading volumes at scale, unmasking sensitive data, capturing
  packets, or causing destructive impact such as deleting or encrypting
  resources and disabling recovery. Reads the actor, the destination, and the
  reversibility to tell routine backup, replication, and decommissioning apart
  from data crossing the account boundary or an irreversible wipe, and decides
  escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - cloud
    - exfiltration
    - destruction
    - impact
---

# Triage Steps

This class fires on the terminal action — data leaving the account or being destroyed — so the stakes are high, but so is the volume of legitimate backup, DR, replication, and decommissioning traffic that does exactly these calls all day. The fact that a snapshot was shared or a resource deleted is not the signal. The signal is where the data went and whether the action can be undone: a share to a known internal account is routine, a share to an external account no one recognizes is not; a change-managed deletion is routine, wiping the recovery path is not. Triage here is reading destination and reversibility and deciding whether it looks like a backup pipeline doing its job or someone walking data out the door or burning it down — escalate or dismiss. This class turns on data leaving the account or being destroyed, and on breaking the protections around depended-on data — encryption, recovery, or backups — distinct from blinding the account's visibility by disabling logging or detection configuration, which is a different class. A destructive wipe of the store that holds the audit logs — mass-deleting the objects in the log bucket or vault — is a data wipe owned here by its activity, even though the data is logs; turning off the trail that writes to it is the other class.

Start from this detection's track record on this actor and resource — a share rule that fires whenever the backup role copies to the DR account and is always closed benign starts the call near dismiss — then read the leads below. None is required on its own; they stack, and a single strong one (a snapshot shared to an unknown external account, or recovery turned off on production data) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Data crossing the account boundary.** A snapshot, disk, or AMI shared or exported to an external or unknown account, or a resource not meant to be public made publicly accessible: `ModifySnapshotAttribute` adding an external account ID, a bucket policy opened to `*` on a private or sensitive store, an image shared org-wide. Data leaving to an account nobody recognizes — not on the trusted allowlist or in inventory — is the top signal; a malicious or suspicious reputation verdict on an external IP or endpoint tied to the transfer sharpens it further.
- **A bulk pull by the wrong actor.** Large-volume reads or exports from a sensitive store — the data-security context flags it (Cyera datastores, Wiz sensitive-data, high-business-impact) — by an actor that is not the backup or DR role: a human or compute identity downloading volumes at scale, unmasking sensitive columns, or capturing packets. Backup runs on a pattern; an off-role bulk pull does not.
- **Irreversible destruction of depended-on data.** Encryption disabled, KMS keys deleted, recovery or backups turned off, or resources wiped — `DeleteDBCluster`, `DeleteBackupVault`, mass `DeleteObject`, a key scheduled for deletion. This is the ransomware or denial shape, and it escalates on its own.
- **It follows recon or secret access.** The same actor swept the account or pulled secrets in the same window, then exported or destroyed. Casing followed by data leaving or being wiped is the chain that confirms intent.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **The actor explains it.** A confirmed backup, DR, or replication identity — the identity directory (Graph/Okta users, service-principals) confirms which it is — or an approved admin performing a change-managed action inside a window.
- **The destination is known.** The share or export targets an internal account or one on the trusted allowlist — recognized and in inventory — not an external or unknown account, and no private or sensitive resource was made public.
- **It matches the baseline and schedule.** The same actor, destination, and volume have appeared here before as scheduled backup or replication; authorized data-governance unmasking within baseline; actions against non-production or test resources. A resource whose documented purpose is public — a static-site or CDN-origin bucket the baseline already shows as open — re-opened to `*` by a named IaC identity on its deploy cadence is the deploy re-applying a known state, not data being newly exposed.
- **Reversible, not destructive.** A copy or export that leaves the source intact, or a deletion that left encryption, keys, and recovery in place — not a wipe of the recovery path.
- **Clean history.** Prior similar actions by this actor closed benign, with nothing new in the destination or volume this time.

To confirm a lead instead of guessing, pull the thread: did the same actor sweep the account or pull secrets just before this, and is the destination account one you can tie to a known backup or partner relationship? Corroboration turns a suspicious export into a confirmed one.

# Output

## Decision
- **escalate:** a snapshot/disk/AMI shared or exported to an external or unknown account, or a private or sensitive resource made public, a bulk pull from a sensitive store by a non-backup actor, or encryption disabled, recovery removed, or resources destroyed on depended-on data — especially when it follows recon or secret access by the same actor.
- **dismiss:** a confirmed backup/DR/replication identity exports to a known internal account on schedule, shares to a trusted-account allowlist, a named IaC identity re-applies a documented-public resource's known state, or an approved admin performs a change-managed deletion that leaves recovery intact, within baseline. A dismiss is a positive call that the export or deletion is benign, made with that context in hand — an actor you confirmed as the backup or DR role, a destination you recognized on the allowlist or in inventory; a destination you couldn't tie to a known account or an actor you couldn't confirm is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or the destination is external or unknown, a private or sensitive resource is made public, or recovery is destroyed — escalate.

## Evidence
The actor and whether it is the backup/DR role, an approved admin, or a human/risky identity; the destination account and whether it is external, on the allowlist, or in inventory; whether any external IP or endpoint tied to the transfer carries a reputation verdict; whether a public exposure hit a resource meant to be public or a private one; the volume and sensitivity of what moved and whether the data-security context flags it; whether the action is irreversible (encryption disabled, keys/recovery deleted); schedule and baseline fit; and any preceding recon or secret access.

## Reasoning
Name the leads that decided it and how they stacked — a human key pulling secrets then sharing a production snapshot to an unknown external account is escalate on its own; the backup role exporting to the DR account on its usual schedule is dismiss.
