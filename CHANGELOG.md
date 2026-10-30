# Changelog

## 0.2.0 - 2026-10-30

- New: **baseline-diff orphan-executable detection** -
  `weblogchecker analyze suspect.log --baseline old.log`.
  Supply a trusted older log from the same site and
  weblogchecker reports executable paths (.php / .phtml /
  .cgi / .asp / .jsp and kin) that appear for the **first
  time** versus the baseline: exactly the unknown-named shell
  no filename blocklist can know about. Each first-seen path
  is scored on five stacked weak signals available in the log
  alone - answered 2xx/3xx, POST/PUT used, referrer-less,
  hit by at most 2 IPs, located under an upload/cache/temp
  directory - and carries its full evidence: which signals
  fired, request/IP/success/POST counts, first-seen
  timestamp, and the raw log lines. Findings use the
  scanner-family delta vocabulary (`"delta": "NEW"`).
- Severity discipline for the new class: first-seen alone is
  a LOW note - medium requires three stacked signals, high
  requires four or more, and confidence never exceeds
  medium, because the signals are circumstantial. A path
  whose first hit arrived from a wp-admin page is treated
  as admin-introduced (plugin install, core update): capped
  at low, and dropped entirely when its stack is thin. An
  executable present in the baseline is never flagged as
  first-seen.
- The false-positive gate now covers the pair case too: the
  test suite ships a normal busy WordPress baseline + later
  log (plugin installed through wp-admin, a contact form
  posting to a new admin-post.php handler from many
  visitors, a new post) and asserts the combined report
  contains **zero medium/high findings**.
- Reports (JSON and text) state the baseline used and how
  many executable paths it contained; without `--baseline`,
  analysis is byte-for-byte the 0.1.0 behaviour.

## 0.1.0 - 2026-10-30

First release.

- `weblogchecker analyze <access.log>` streams Apache combined /
  common and nginx default access logs (plain or .gz, or stdin
  via `-`) and reports compromise indicators grouped into an
  incident timeline by IP + path, in text or JSON.
- Detection classes, each with severity, confidence and
  remediation text: known webshell filenames answering requests
  (c99 / r57 / FilesMan / b374k / WSO and generic shell names),
  the phpunit `eval-stdin.php` UnitTest shell abused in the
  October 2026 php2shell wave, executables answering inside
  upload directories, POST/PUT to static files, exploitation
  patterns in request URIs (traversal, code-execution keywords,
  stream wrappers, long base64-style tokens), self-identified
  scanner user-agents, and wp-login / xmlrpc brute-force bursts
  including a possible-success pattern.
- Exit codes: 0 = no indicators, 1 = indicators found,
  2 = usage error.
- False-positive discipline is a tested property: the bundled
  fixture of a normal busy WordPress day (admin work, plugin
  updates, cron, wp-admin uploads) produces zero findings.
- Standard library only; no network access; the analyzed log is
  never modified.
