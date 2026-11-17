---
name: Web Reflected Payload Noise
description: From an engineer-approved benign verdict on an injection-unusual-response-size alert, propose one change that removes the false-positive class - discount reflected payload length, or require a deeper baseline - rather than excluding a path. Proposes only.
type: tuning
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, injection, anomaly, detection-tuning]
---

# Tuning Methodology

Runs only on a verdict an engineer has approved - an unreviewed verdict is not ground
truth. Returns a proposal for a person to apply or reject; it changes nothing.

- **Benign, reflection** (H-reflected) - `modify` the size comparison to subtract the
  request's payload length before checking the range. This fixes every page that echoes
  input at once, and an exploit that returns a file still grows the body by far more
  than its payload.
- **Benign, a dynamic page with a thin baseline** (H-dynamic) - `modify` the minimum
  sample count upward, with the numbers.
- **Benign, a page that is dynamic by design with a deep baseline** - `exclude` that site
  and exact path. Never a pattern, never a whole site.
- **Malicious** - no change, the detection worked. If the investigation shows the same
  attack evading through another payload class, `include` it.

Never propose a change that would have hidden a malicious verdict.

# Output

## Action
**modify** for reflection or a thin baseline (the usual cases); **exclude** only for one
exact path that is dynamic by design; **include** for a payload class that evaded.
Propose nothing when the detection worked.

## Target
The unusual-size detection - its size comparison, its minimum baseline, or its
exclusion list.

## Value
One line: the comparison with payload length subtracted, the new minimum sample count, or
the exact site and path to exclude.

## Evidence
The approved verdict and engineer note, the size difference against payload length, the
baseline's sample count and range, and which past alerts would and would not have fired
under the change.

## Reasoning
The mechanism, and what still alerts: discounting the payload's own length removes the
echo without hiding an exploit, because a file or a dump grows the body by far more than
the request that asked for it.
