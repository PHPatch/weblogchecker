# weblogchecker

**Your web server logs already know if you were attacked. weblogchecker reads them.**

`phpscan` tells you whether your PHP is exposed. `phpscan hunt` searches the
webroot for shells. weblogchecker answers the third question — *did anyone
actually use them?* — from the one record most sites already have and nobody
reads: the access log.

It streams Apache and nginx access logs **you own**, finds the interactions
that matter — a webshell answering requests, a brute-force burst that ends in
a redirect, an exploit pattern that got a 200 — and reports each one with
**severity, confidence, the actual log lines as evidence, and what to do
about it**.

```bash
weblogchecker analyze /var/log/apache2/access.log
```

Exit codes: `0` = no indicators, `1` = indicators found, `2` = usage error.
Add `--format json` for machine-readable output, `--since 2026-10-01` to
limit the window. `.gz` logs are read directly; `-` reads stdin.

## Install

One line, from PyPI (Python 3.11+, standard library only — zero dependencies):

```bash
pip install weblogchecker
```

> **First PyPI release pending.** Until the PyPI trusted publisher is
> configured, install the identical code from GitHub:
> `pip install git+https://github.com/PHPatch/weblogchecker.git`
> (or download the signed release tarball below). The `pip install
> weblogchecker` line above works as soon as the first PyPI release lands.

On systems that refuse with "externally-managed-environment"
(Debian/Ubuntu and Homebrew Pythons), use pipx instead:

```bash
python3 -m pip install --user pipx   # if you don't have pipx yet
pipx install weblogchecker
```

Signed releases (sdist + wheel + PGP signatures + SBOM) are on the
[GitHub releases page](https://github.com/PHPatch/weblogchecker/releases).
Verify signatures with the key in `pgp-key.asc` — fingerprint
`BAA1 586A AD37 18C0 CE41 D288 FE23 A624 54E3 5307`. See `SECURITY.md`.

## What it detects

| Pattern in your log | Severity / confidence | Why it matters |
| --- | --- | --- |
| Known webshell (c99, r57, FilesMan, b374k, WSO) answering 2xx | high / high | The shell exists and served a request |
| Same names probed but 404/403 | low / low | Someone looked; nothing found — context, not alarm |
| `eval-stdin.php` (phpunit) answering | high / high | The UnitTest shell from the Oct 2026 php2shell wave executes POSTed code |
| Executable (.php etc.) inside `/uploads/`, `/media/`, `/files/`… answering, esp. POST | high / high | Upload dirs must never run code |
| POST/PUT to a static file (.jpg, .css…) answered 2xx | high / medium | Browsers don't POST to images; the "image" is often a script |
| Exploit pattern in the URI (traversal, `eval(`, `php://`, long base64 token) answered 2xx | high / medium | The attempt may have worked |
| Same patterns blocked / 404 | low / low | Background noise; useful only as campaign context |
| Brute-force burst on wp-login.php / xmlrpc.php (≥20 POSTs / 10 min) | medium / medium | One IP, inhuman pace |
| A 302 inside that burst after repeated failures | high / medium | The shape of a correct password — possible takeover |
| Scanner user-agents (sqlmap, nuclei, nikto…) | low / low | Informational; scanning is not compromise |

Every finding class carries remediation text: quarantine the file, rotate
credentials, review everything that IP touched. Webshell findings point at
the companion tool — **`phpscan hunt`** (`pip install phpscan`,
[github.com/PHPatch/phpscan](https://github.com/PHPatch/phpscan)) — which
scans the webroot itself for the shells these log patterns point at.

## Honesty rules

This tool was built under the same doctrine as phpscan:

- **Indicators, not verdicts.** A finding says "this pattern appears in your
  log, with this confidence" — never "you were hacked". A clean result says
  "none of these patterns appear in this window" — never "you are safe".
  Attackers who arrive over SSH, a stolen session cookie, or a log the
  server never wrote leave nothing for this tool to find.
- **Failed attempts stay low.** A 404 probe is someone knocking, not someone
  inside. Severity follows the server's answer, not the request's intent.
- **False-positive discipline is tested, not promised.** The test suite
  ships a fixture of a normal busy WordPress day — admin logins, plugin
  updates, wp-cron, image uploads through wp-admin, Jetpack xmlrpc pings —
  and asserts it produces **zero findings**. If a detector ever fires on
  ordinary admin work, that's a bug; please report it.
- **Read-only and offline.** weblogchecker opens no network connections and
  never modifies the log it analyzes. Your logs — which reveal your
  visitors' IPs — never leave your machine.

## Performance

Parsing is line-streaming: the file is never loaded into memory, and
aggregation keeps at most five evidence lines per finding. Measured on this
project's fixture generator (366,306 lines, 72 MB of realistic combined
log): **7.6 seconds, 12.8 MB peak RSS** on a modest VM. A 2 GB log is the
same memory, proportionally more time.

## Example

```
$ weblogchecker analyze access.log
weblogchecker 0.1.0 - access-log compromise analysis
Log: access.log
Lines read: 13 | parsed: 13 | unparseable (skipped): 0

Indicators found. These are leads for investigation, not proof of
compromise: work through the findings in severity order ...

SUMMARY: 10 findings (4 high, 1 medium, 5 low) across 9 incidents, 2 IPs flagged

INCIDENT TIMELINE (grouped by IP + path):
  [HIGH] 198.51.100.66 /wp-content/uploads/2026/10/c99.php
       classes: webshell-access, exec-in-upload-dir | requests: 6 | ...
  ...

1. [high severity / high confidence] Known webshell filename answered a request
   198.51.100.66 /wp-content/uploads/2026/10/c99.php - 3 request(s), ...
   | 198.51.100.66 - - [28/Oct/2026:03:13:40 +0000] "GET /wp-content/..." 200 ...
   Remediation: Treat the named file as a live webshell until you have
   proven otherwise. Locate it in the webroot and quarantine it ...
```

## The family

- [phpscan](https://github.com/PHPatch/phpscan) — is your PHP exposed?
  (version/CVE verdicts, composer audit, `hunt` for shells on disk)
- **weblogchecker** — did anyone exploit it? (this tool, from your logs)
- wpchecker — is your WordPress plugin stack exposed? (companion scanner)

All free, all open source, none of them send exploit probes.

## License

MIT — see `LICENSE`. Security reports: see `SECURITY.md`.
