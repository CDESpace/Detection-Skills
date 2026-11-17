---
name: Web Injection Unusual Response Size
description: Triage an injection, traversal or SSRF request that a web server answered 200, using access logs alone. Escalates when the response size falls outside that path's learned normal range - the one outcome signal an access log carries.
type: triage
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, apache, nginx, injection, traversal, ssrf, owasp-a03, owasp-a10]
---

# Triage Steps

Applies when the only evidence is the access log: no WAF verdict, no application log, no
response body. An injection-shaped request answered `200` is the norm, not the
exception - most apps ignore a parameter they do not expect and serve the normal page.
The log cannot show what the body said, but it does show **how big it was**
(`%b` / `$body_bytes_sent`), and an exploit that worked usually changes that.

**Learn what normal is, from clean traffic only.** For each site and path, keep the
range of sizes of `200` responses to requests no rule fired on. Never learn from flagged
requests, or an attacker can widen the range just by repeating the attack. Treat a path
with fewer than about five clean samples as having no baseline: its size means nothing
yet.

**Leads that point to a real threat:**

- The response size is outside the learned range by more than a margin (the larger of
  about 200 bytes or 10%): the payload changed what came back.
- The growth is roughly the size of the file the payload named (`/etc/passwd`,
  `win.ini`), or the size of a response a database error or internal URL would produce.
- The same source sent the same payload elsewhere and got normal sizes - this path
  is the one that reacted.

**Leads that rule it out:**

- The size is inside the learned range: the app served its usual page.
- The path has too thin a baseline to judge.
- The growth is about the payload's own length - the page echoes the query string back
  (search pages, error messages). That is reflection, not execution.

# Output

## Decision
- **escalate:** a 200 to an injection, traversal or SSRF request on a path with a real
  baseline, with a size outside the learned range by more than the margin and not
  explained by the payload's length.
- **dismiss:** the size is in range, the baseline is too thin, or the growth matches the
  payload's length. Dismissals are logged and reversible. If the size moved and you
  cannot explain why, escalate.

## Evidence
The payload class, the response size, the path's learned range and sample count, the
difference against the payload's length, and the source's results on other paths.

## Reasoning
Which lead decided it - for example "the traversal named `/etc/passwd` and the response
grew by 1,870 bytes against a 4,100-4,180 range from 212 samples, far more than the
40-byte payload: the file was likely returned".
