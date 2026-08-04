---
name: Risk Based Alerting
description: Triage a risk-based alert where an entity's aggregated risk score
  crossed a threshold — a risk notable built from accumulated risk events across
  detections, sources, or MITRE tactics. Reads the mix of contributing events —
  diversity, progression, whether any stands alone — against the object's score
  baseline to tell an accumulating attack chain apart from one noisy rule or a
  score multiplier, and decides escalate or dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - risk
    - risk-based-alerting
    - aggregation
    - correlation
    - risk-score
---

# Triage Steps

This class fires on a score, not on a behavior: a risk object — a user or a system — accumulated enough risk score from individual risk events that an aggregation rule crossed its threshold (a score ceiling over 24 hours, events from multiple sources over days, multiple MITRE tactics in a window). The score itself is not the signal: five firings of one noisy rule add up to the same number as five stages of an intrusion, and a privileged-user multiplier can push routine activity over the line with no new behavior at all. The signal is what the score is made of. The alert is a container — its truth lives in the risk events inside it — so triage here is opening the container and deciding: did varied, progressing suspicious behavior build up on this entity, or did routine noise just add up?

Begin with this aggregation's track record on this risk object — an object that crosses the threshold on a recurring cadence with the same contributor mix and always closes benign starts the call near dismiss — then read the contributing events for the leads below. None is required on its own; they stack, and a single strong one (a contributor that would escalate alone, a tactic progression) can carry the call.

**Leads that point to a real threat** — what to look for in the data:

- **Diverse contributors telling one story.** The score comes from multiple distinct risk rules, across different sourcetypes or domains, all landing on the same object in the window — endpoint execution plus authentication anomaly plus outbound traffic reads as one actor moving, not one detector repeating. Diversity across MITRE tactics is the strongest form of this: distinct tactics on one object is the pattern aggregation rules exist to catch.
- **Progression in time order.** The contributors sequence across the kill chain rather than clustering in one stage — reconnaissance, then credential access, then command-and-control or exfiltration. A later-stage contributor following earlier-stage ones carries more weight than any single score; the order is the story.
- **A contributor that stands alone.** One contributing event that would merit escalation by itself — a credential dump, a connection to a known-bad destination, activity on a terminated account. The aggregation just surfaced it; escalate on that contributor's strength without needing the rest of the sum.
- **A score burst against a flat baseline.** The object's risk history sits near zero and jumps to threshold within hours. New accumulation on a quiet object is behavior changing; the same total riding near threshold every week is not.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **One noisy rule did all the accumulating.** The contributors are N firings of the same risk rule on the same object with the same fields — repetition, not diversity. The aggregate adds nothing beyond that single detection; judge it as that one alert, and a rule already known noisy on this object makes the sum score inflation, not signal.
- **A recurring crossing with a known mix.** This object crosses the threshold on a recognizable cadence — scan days, backup windows, batch jobs — with the same contributor mix each time, and prior crossings closed benign with nothing new in this one.
- **A multiplier pushed it over, not new behavior.** The threshold was crossed because a risk factor — a privileged-user or sensitive-asset multiplier — inflated the scores of routine events the object generates anyway. The multiplier makes the entity worth watching; it does not make the same events suspicious. Take the multiplier away: if the underlying activity would not have alerted on its own, the crossing came from the boost, not from behavior.
- **Every top contributor is positively explained.** Each of the events that carried the score maps to confirmed benign context — a change window, a vulnerability scanner doing its rounds, a service account doing its documented job — and no contributor survives scrutiny on its own.

To confirm a lead instead of guessing, pull the thread: the notable is only as credible as its contributors, so pull the contributing risk events, put them in time order, and read the top two or three like the alerts they are — does any stand on its own, does the sequence progress across tactics, and does the mix differ from this object's previous crossings? An aggregate of explained events is explained; an aggregate hiding one real event is that event's escalation.

# Output

## Decision
- **escalate:** tactic- or source-diverse contributors forming a time-ordered progression on one object, any single contributor that merits escalation on its own, or a score burst far off the object's flat baseline — especially diversity and progression together.
- **dismiss:** the accumulation is a single rule repeating, a recurring baseline crossing with a historically-benign contributor mix, or multiplier-inflated routine activity, and the top contributors are each positively explained. A dismiss is a positive call that the accumulation is benign, made with that context in hand — contributors you actually read and explained, a recurring mix you matched against prior crossings; a contributor you couldn't pull or a score history you couldn't establish is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; when the benign context is missing or you're unsure — or any single contributor looks real on its own — escalate.

## Evidence
The mix of contributing risk events (distinct rules, sourcetypes, and MITRE tactics vs a repetition count of one rule), the risk object and its type and privilege (and any risk-factor multiplier applied), the time-ordered sequence of contributors, the strongest single contributor and whether it stands alone, and the object's score history and how prior crossings closed.

## Reasoning
Name the mix that decided it and how the leads stacked — four distinct rules progressing from discovery to credential access to outbound on one host is escalate on its own, while a weekly threshold crossing built from one noisy rule's repeats on a scan server, matching every prior benign crossing, is dismiss.
