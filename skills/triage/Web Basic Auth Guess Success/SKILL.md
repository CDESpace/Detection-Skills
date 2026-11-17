---
name: Web Basic Auth Guess Success
description: Triage a 2xx after a run of 401s from one source on one HTTP basic-auth realm, from web server access logs alone. Escalates only when the failures carried credentials - a browser's pre-prompt 401s do not.
type: triage
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, apache, nginx, basic-auth, credential-guessing, owasp-a07]
---

# Triage Steps

Applies to alerts built from combined-format access logs where a source got a 2xx on a
basic-auth protected path after several 401s on the same host and path.

**The signal that matters.** `%u` (Apache) / `$remote_user` (nginx) is the username from
the request's `Authorization` header. On a 401 it is the name that was tried; with no
header it is `-`.

- **Bare 401** (`-`): the client did not send credentials. Every browser does this
  first, and often several times in parallel (page, favicon, prefetch) before it shows
  the password prompt. A guesser cannot produce these as guesses.
- **Credentialed 401** (a name): a username and password were sent and refused. This is
  what guessing looks like.

Confirm your server logs the name on a refused request before relying on this: count
401s with and without a name in a week of logs. Both should be present.

**Leads that point to a real threat:**

1. The source is external and not a documented scanner or monitor within its published
   range.
2. At least N **credentialed** 401s (N=5 is a reasonable start) on the same host and
   path, inside a window (1 hour), then a 2xx.
3. The rule has not already fired for this source and path inside the window.

**Leads that rule it out:**

- Every 401 before the success was bare. Normal pattern: a burst within a few seconds,
  a human-scale pause, one successful login, then asset loads with a same-site referer.
- The source is a known automation from its fixed range, failing with one consistent
  username (a stale stored password) - this is a broken client, not a guess; route to
  its owner.

# Output

## Decision
- **escalate:** N or more credentialed 401s on the same host and path inside the window,
  then a 2xx, from a source that is not a documented scanner or monitor.
- **dismiss:** every 401 before the success was bare, or a known automation from its
  fixed range failing on one stale username. Dismissals are logged and reversible. If
  credentials were sent and the context is unclear, escalate.

## Evidence
The count of bare and credentialed 401s, the number of distinct usernames tried (as
counts, not the names), the time span of the run, the 2xx that followed, and what the
source did right after it.

## Reasoning
Which lead decided it - for example "7 credentialed 401s with 5 distinct usernames over
40 s, then a 200 for a sixth: guessing that worked", or "16 bare 401s in 6 s, then one
login and asset loads with a same-site referer: a browser meeting its prompt".
