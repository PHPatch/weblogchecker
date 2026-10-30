# Changelog

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
