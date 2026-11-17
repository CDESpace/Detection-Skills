---
name: Web Auth Pre-Prompt Noise
description: From an engineer-approved benign verdict on a basic-auth guess-success alert, propose one change that removes the whole false-positive class rather than excluding one source. Proposes only.
type: tuning
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, basic-auth, detection-tuning]
---

# Tuning Methodology

Runs only on a verdict an engineer has approved - an unreviewed verdict is not ground
truth. Returns a proposal for a person to apply or reject; it changes nothing.

- **Benign, the 401s were bare** - the detection is counting requests a guesser cannot
  make. `modify`: count only credentialed 401s toward the threshold. This fixes it for
  every user at once. Do not exclude the source address: residential and mobile
  addresses change hands, and an exclusion would blind the rule to the next holder.
- **Benign, one automation with a stale password** - `exclude` by its published range
  plus user agent, and tell its owner. Keep counting its lines.
- **Benign, a user mistyping** - usually no change; a threshold of 5 credentialed
  failures already tolerates ordinary typos. Raise it only with evidence.
- **Malicious, fired late or nearly missed** - `modify` the threshold or window, with
  the numbers that justify it.

Never propose a change that would have suppressed a malicious verdict.

# Output

## Action
**modify** when the 401s were bare (the usual case); **exclude** only for a known
automation by its published range plus user agent. When a mistyping user already fits
under the threshold, propose nothing.

## Target
The guess-success detection's 401 counter - the condition that decides which 401s count
toward the threshold - or, for an automation, the detection's exclusion list.

## Value
One line. For the bare-401 case: count a 401 only when the logged user field is not
`-`. For an automation: its published address range and exact user agent, together.

## Evidence
The approved verdict and engineer note, the bare and credentialed 401 counts from the
alert, and which past alerts would and would not have fired under the change.

## Reasoning
The mechanism: a browser always sends one bare request before its prompt, so bare 401s
measure page loads, not guesses. Counting only credentialed ones removes that whole
class for every user, and a guesser - who must send credentials to guess - still fires.
