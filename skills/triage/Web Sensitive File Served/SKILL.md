---
name: Web Sensitive File Served
description: Triage a 200 for a path that names a sensitive file (.env, .git/config, database dumps, backups, private keys) from web server access logs. Escalates only when the file really exists under the site's document root - a catch-all route that answers 200 for every path does not count.
type: triage
version: 1.0.0
metadata:
  author: Jason Payne
  labels: [web, access-log, apache, nginx, sensitive-files, information-disclosure, owasp-a01, owasp-a05]
---

# Triage Steps

Applies to alerts from combined-format access logs where a request for a path a
sensitive-file signature names (`/.env`, `/.git/config`, `/backup.sql`, `/id_rsa`,
`/wp-config.php.bak`, ...) was answered `200`.

Scanners ask every site on the internet for these paths, all day. The request arriving
is not the signal. What matters is whether the server actually handed over a file.

**The trap: catch-all routes.** A single-page app, a framework's fallback route or a
custom "not found" page that returns `200` answers *every* path with the same page. On
those sites "sensitive path + 200" fires on every scanner and means nothing. Two checks
cut through it, and neither needs more than the log and read access to the docroot:

- **Does the file exist?** Decode and normalise the path, resolve it under the vhost's
  `DocumentRoot`, and check it is a real file there now. A path that resolves outside
  the root (traversal) is not "inside the root".
- **Does the size match?** Compare the response size (`%b` / `$body_bytes_sent`) with
  the size of the site's usual fallback page. The same size as the index page for
  `/.env` is the fallback, not the file.

**Leads that point to a real threat:**

- The file exists under the document root and the response size is close to its size
  on disk.
- The source then asked for related paths (`/.git/HEAD`, then `/.git/config`, then
  objects), which is someone walking a repository that answered.
- The file class carries secrets on its face: environment files, private keys, database
  dumps, cloud credential files.

**Leads that rule it out:**

- The file does not exist under the document root - the 200 came from a catch-all.
- The response size equals the site's fallback or index page.
- The path is public on purpose and documented (`/.well-known/security.txt`, a published
  PGP key, a sitemap) and the signature is simply too broad for it.

When the site is an application with no document root to check, the existence check
cannot answer. Do not escalate on the path alone; count it as unverifiable and say so,
because an alert nobody can confirm costs more trust than it buys.

# Output

## Decision
- **escalate:** the file exists under the document root and was served with a matching
  size, from a source that is not a documented scanner of your own.
- **dismiss:** the file does not exist, the size is the fallback page's, or the path is
  public by design. Dismissals are logged and reversible. If the file exists and you
  cannot tell what is in it, escalate.

## Evidence
The path and which signature matched, the response status and size, whether the file
exists under the document root and its size on disk, the fallback page's size, and
whether the source asked for related paths.

## Reasoning
Which check decided it - for example "`/.env` exists in the docroot and 1,214 bytes were
served against 1,214 on disk: the file was disclosed", or "every probe path returned the
same 3,402-byte page and none exists on disk: a catch-all route".
