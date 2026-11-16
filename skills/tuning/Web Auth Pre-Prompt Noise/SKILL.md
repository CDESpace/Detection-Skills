---
name: Web Auth Pre-Prompt Noise
description: From an engineer-approved benign verdict on a basic-auth guess-success alert, propose one change that removes the whole false-positive class rather than excluding one source. Proposes only.
type: tuning
version: 1.0.0
metadata:
  author: <your name>
  labels: [web, access-log, basic-auth, detection-tuning]
---

# Web Auth Pre-Prompt Noise

Runs only on a verdict an engineer has approved - an unreviewed verdict is not ground
truth. Returns a proposal for a person to apply or reject; it changes nothing.

## Choose

- **Benign, the 401s were bare** - the detection is counting requests a guesser cannot
  make. `modify`: count only credentialed 401s toward the threshold. This fixes it for
  every user at once. Do not exclude the source address: residential and mobile
  addresses change hands, and an exclusion would blind the rule to the next holder.
- **Benign, one automation with a stale password** - `exclude` by its published range
  plus user agent, and tell its owner. Keep counting its lines.
- **Benign, a user mistyping** - usually `none`; a threshold of 5 credentialed
  failures already tolerates ordinary typos. Raise it only with evidence.
- **Malicious, fired late or nearly missed** - `modify` the threshold or window, with
  the numbers that justify it.

State the expected effect - which past alerts would and would not have fired - and
never propose a change that would have suppressed a malicious verdict.

## Output

{"action": "exclude|include|modify|fork|none", "target": "...", "value": "...",
 "expected_effect": "...", "evidence": ["..."], "reasoning": "..."}
