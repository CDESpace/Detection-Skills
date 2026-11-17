---
name: Web Public-By-Design File Noise
description: From an engineer-approved benign verdict on a sensitive-file-served alert, propose one change - usually an exact site-and-path exclusion for a file that is public on purpose, or splitting a file class that deserves its own severity. Proposes only; never hides a disclosed secret.
type: tuning
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, sensitive-files, detection-tuning]
---

# Tuning Methodology

Runs only on a verdict an engineer has approved - an unreviewed verdict is not ground
truth. Returns a proposal for a person to apply or reject; it changes nothing.

- **Benign, public on purpose** (H-intended) - `exclude` that site and that exact path.
  Never a pattern and never a whole site: the next file to match a broad exclusion may be
  a real secret.
- **Benign, a stub or decoy** (H-decoy) - usually no change. The file exists, and serving
  it is the site owner's choice. If it is a honeypot, the alert is the point.
- **Malicious or suspicious** - usually no change, because the detection worked. If the
  same class of file showed up under names the signature missed, `include` them.
- **One file class deserves its own severity** (private keys and credential files over
  editor backups) - `fork` the detection by class.
- **The alert fired because a catch-all route answered 200** - the existence check was
  missing or broken for that site. `modify` the check, not the path list.

Never propose a change that would have hidden a malicious or suspicious verdict.

# Output

## Action
**exclude** for a file that is public on purpose; **include** for missed names in an
exposed class; **fork** to split a class by severity; **modify** for a broken existence
check. Propose nothing for a stub or a detection that worked.

## Target
The sensitive-file detection - its exclusion list, its signature list, or its
file-exists check, depending on the action.

## Value
One line: the exact site and path to exclude, the names to include, the class to fork
off, or the corrected existence condition.

## Evidence
The approved verdict and engineer note, the file's class and whether it is documented as
public, and which past alerts would and would not have fired under the change.

## Reasoning
The mechanism, and what still alerts after it: an exact-path exclusion silences one
documented public file while every other sensitive name on the same site keeps firing.
