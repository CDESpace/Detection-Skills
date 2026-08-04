---
name: macOS Clickfix Loader
description: Triage a macOS alert for a suspicious download, script execution,
  or outbound request coming from a user's own terminal — the ClickFix pattern,
  where a lure page talks the user into copying and pasting attacker commands,
  so the infection looks like normal user behavior because the user ran it
  themselves. Reads the shape of the command, what the user was doing just
  before, and whether this user would ever write such a command, to tell a
  pasted loader apart from a person's real workflow, and decides escalate or
  dismiss.
type: triage
version: 1.0.0
metadata:
  author: Vega Security
  labels:
    - endpoint
    - macos
    - clickfix
    - loader
    - social-engineering
---

# Triage Steps

Use this when a suspicious-download, suspicious-execution, or suspicious-outbound-request alert fires from an interactive session on a macOS user endpoint. The trap in this class is that everything looks like normal user behavior — because it is the user. ClickFix is social engineering: a page the user trusted (a fake CAPTCHA, a "fix your microphone" prompt, a verification step) tells them to copy a command and paste it into Terminal, and they do. There is no exploit and no malicious parent process — the user's own shell, under the user's own account, fetches and runs the attacker's code. EDR sees an interactive terminal doing what terminals do, which is exactly why these get waved off as developer activity. Triage here is deciding one thing: did this user run this command because it is their job, or because a page told them to?

Track record helps less than usual here — "this user's terminal has fired alerts before and they were fine" is exactly the cover this technique hides behind. Judge the command and the story around it, not the fact that a person was at the keyboard.

**Leads that point to a real threat** — what to look for in the data:

- **The command reads pasted, not written.** A single long one-liner appearing in an interactive shell that fetches, decodes, and executes in one breath — `curl` piped to `sh` or `osascript`, a base64 blob decoded into an interpreter, nothing saved to disk. Real people build up to commands like this; a lure hands it over finished. Extra tells that reinforce it: a TLS bypass flag, a browser User-Agent on a script fetch, an odd or brand-new domain, a per-victim tag in the URL.
- **The browser was there a moment before.** The terminal (or `osascript`) activity starts right after browsing — the user was on a page, then their first terminal command is a remote fetch. That sequence is the lure working: page instructs, user pastes.
- **The user would never write this.** The account belongs to someone in finance, HR, sales — anyone whose role and history include no terminal use — and the identity directory and host baseline show no developer tooling or shell habit. A one-liner interpreter fetch from that person's session is someone else's command in their hands.
- **Loader behavior follows.** A second-stage fetch right after the first, in-memory execution with nothing on disk, then persistence, keychain access, or credential touches on the same host and user. The chain moving means the paste detonated.

**Leads that rule it out** — benign context you can actually see in the data; if the data doesn't show it, you don't have it:

- **This is genuinely the user's workflow.** The account is an engineer or admin, the host carries developer tooling, and the fetch source is a recognized install domain (a package manager, a vendor's documented install, a source-control host) that this user or fleet has pulled from before. Developers really do run `curl | sh` — the source and the person are what make it theirs.
- **A management agent ran it, not a person.** The parent is the MDM or software-management agent executing its own script in a management context — not an interactive terminal session. That is fleet operations, not a paste.
- **An authorized replay.** A known analysis or detonation host and a security or research identity reproducing a published lure on purpose — both confirmed in the inventory and directory, not assumed.

To confirm a lead instead of guessing, pull the thread: what was the user doing in the minutes before the command — is there browsing right up against it? Check the fetch domain's reputation and age. And look at what came after: a second stage, something persisting, the keychain touched. A pasted one-liner from a fresh domain right after browsing, on an account with no shell history, is the pattern complete; the same fetch from a documented install source on a developer's machine is a person doing their job.

# Output

## Decision
- **escalate:** a fetch-and-execute one-liner in an interactive session that the actor's role and history cannot explain, browsing immediately before it, an unrecognized or fresh source domain, or any second-stage or post-execution activity after it — the user running it themselves is the technique, not the alibi.
- **dismiss:** the command, the source domain, and the person line up as real workflow — a developer or admin pulling from a recognized install source they have used before — or the run belongs to a management agent or a confirmed security replay. A dismiss is a positive call made with that context in hand — a role you checked, a domain you recognized, a baseline you actually saw; a user you couldn't place or a domain you couldn't account for is not that context, and absence of a bad sign is not proof it's good. Dismiss is logged and reopenable; a failed fetch or a quiet aftermath is not benign proof either — whether it detonated is the investigation's question. When the story doesn't add up or you're unsure, escalate.

## Evidence
The full command line and what it pipes into, the fetch domain and its reputation and age, the parent process (interactive terminal vs management agent), what the user was doing just before, the actor's role from the identity directory and their terminal history on this host, and anything that ran after.

## Reasoning
Name what decided it — a finance user's terminal pulling a script from a week-old domain seconds after browsing, piped straight into an interpreter, is escalate on its own; the same shape on an engineer's machine from a documented install source they've used for months is dismiss.
