"""Indicator data and finding-class metadata for weblogchecker.

The filename / user-agent IOC lists live in data/log_iocs.json
(with their provenance recorded in that file). This module adds
the finding classes: titles, and the remediation text that the
honesty doctrine requires on every class weblogchecker can report.
"""

import json
from pathlib import Path

_DATA = Path(__file__).resolve().parent / "data" / "log_iocs.json"


def _load():
    with _DATA.open(encoding="utf-8") as fh:
        return json.load(fh)


IOCS = _load()

SHELL_NAMES_CANONICAL = frozenset(IOCS["shell_names_canonical"])
SHELL_NAMES_GENERIC = frozenset(IOCS["shell_names_generic"])
SHELL_NAMES_DROPPER = frozenset(IOCS["shell_names_dropper"])
UNIT_TEST_SHELL_PATHS = frozenset(IOCS["unit_test_shell_paths"])
SCANNER_USER_AGENTS = tuple(IOCS["scanner_user_agents"])

# Path fragments (decoded, lower-case) that mark directories whose
# contents should be data, never executable code.
UPLOAD_DIR_MARKERS = (
    "/wp-content/uploads/",
    "/uploads/",
    "/upload/",
    "/media/",
    "/userfiles/",
    "/attachments/",
    "/files/",
    "/images/",
)

EXECUTABLE_EXTS = (
    ".php", ".phtml", ".php5", ".php7", ".phar",
    ".cgi", ".pl", ".asp", ".aspx", ".jsp",
)

STATIC_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
    ".ico", ".css", ".js", ".txt", ".html", ".htm", ".woff", ".woff2",
)

LOGIN_BASENAMES = ("wp-login.php", "xmlrpc.php")

CLASS_INFO = {
    "webshell-access": {
        "title": "Known webshell filename answered a request",
        "remediation": (
            "Treat the named file as a live webshell until you have "
            "proven otherwise. Locate it in the webroot and quarantine "
            "it (do not just delete it - keep a copy with these log "
            "lines for forensics). Scan the whole webroot for more "
            "shells - phpscan hunt (github.com/PHPatch/phpscan) does "
            "exactly this. Then rotate every credential the site "
            "knows (database, admin accounts, salts/keys, FTP/SSH) "
            "and review every request this IP made."
        ),
    },
    "generic-shell-access": {
        "title": "Generic shell filename (shell.php / cmd.php / ...) answered a request",
        "remediation": (
            "A file with a self-describing shell name answered on "
            "your site. Confirm whether you or your team put it "
            "there; if not, quarantine it, scan the webroot with "
            "phpscan hunt, rotate credentials, and review every "
            "request from this IP."
        ),
    },
    "dropper-access": {
        "title": "Single-letter/digit PHP filename answered a request",
        "remediation": (
            "Names like x.php and 1.php are common dropper names, "
            "but they can also be leftover test files. Open the "
            "file and read it: if you do not recognise it, "
            "quarantine it and scan the webroot with phpscan hunt."
        ),
    },
    "unit-shell-access": {
        "title": "UnitTest shell (eval-stdin.php) answered a request",
        "remediation": (
            "eval-stdin.php is the shell abused in the October 2026 "
            "php2shell wave (CVE-2026-109618 / CVE-2026-109619): "
            "it executes whatever PHP code is POSTed to it. If it "
            "answered, assume code execution. Remove the exposed "
            "phpunit copy from the web root (dev dependencies do "
            "not belong in production), quarantine the file, scan "
            "the webroot with phpscan hunt, rotate credentials, "
            "and check whether your PHP version is patched - "
            "phpscan (pip install phpscan) checks that."
        ),
    },
    "exec-in-upload-dir": {
        "title": "Executable file inside an upload/data directory was requested",
        "remediation": (
            "Upload and media directories must never execute code. "
            "Quarantine the named file, scan the webroot with "
            "phpscan hunt, and fix the server configuration so "
            "scripts do not run from upload directories (deny PHP "
            "execution there) - then find how the file got in, "
            "which is usually an upload form or a vulnerable plugin."
        ),
    },
    "post-to-static": {
        "title": "POST/PUT sent to a static file and accepted",
        "remediation": (
            "Browsers do not POST to images, stylesheets or text "
            "files. A 2xx answer usually means the 'static' file "
            "is actually a script in disguise, or a handler is "
            "executing it. Inspect the file on disk, quarantine "
            "it if it is not what its extension claims, and scan "
            "the webroot with phpscan hunt."
        ),
    },
    "exploit-success": {
        "title": "Exploitation pattern in the request URI got a success response",
        "remediation": (
            "The pattern (code-execution keywords, path traversal, "
            "a stream wrapper or an encoded payload) was answered "
            "with a success status, so it may have worked. Preserve "
            "the log, review everything this IP requested before "
            "and after, scan the webroot with phpscan hunt, and "
            "patch or remove whatever component answered."
        ),
    },
    "webshell-probe": {
        "title": "Webshell filenames probed (not found)",
        "remediation": (
            "Someone looked for a shell and the server said no. "
            "On its own this needs no action - the public internet "
            "probes constantly. It matters only if the same IP "
            "also has success findings; review the IP's full "
            "timeline below."
        ),
    },
    "upload-exec-probe": {
        "title": "Executable-in-upload-directory probed (not found)",
        "remediation": (
            "A POST reached for an executable inside an upload "
            "directory and got an error. No action on its own; "
            "check the same IP for success findings."
        ),
    },
    "exploit-probe": {
        "title": "Exploitation pattern in the request URI (blocked / not found)",
        "remediation": (
            "The attempt did not succeed (error status). This is "
            "background noise on most sites. No action needed "
            "unless the same IP also succeeded somewhere - then "
            "treat it as one campaign and follow the success "
            "remediation."
        ),
    },
    "scanner-ua": {
        "title": "Self-identified vulnerability scanner user-agent",
        "remediation": (
            "A tool announced itself (sqlmap, nuclei, nikto and "
            "similar identify themselves by default). Informational "
            "only: scanning is not compromise. If the volume bothers "
            "you, rate-limit or block the IP at your edge - but "
            "check its other findings first."
        ),
    },
    "brute-force": {
        "title": "Login brute-force burst (wp-login.php / xmlrpc.php)",
        "remediation": (
            "One IP posted login attempts far faster than a human. "
            "Confirm the accounts it targeted still have their "
            "owners: force password resets for targeted admin "
            "accounts, turn on two-factor authentication, and "
            "rate-limit or block the IP. WordPress: consider "
            "restricting wp-login.php and xmlrpc.php by IP if "
            "your workflow allows it."
        ),
    },
    "brute-force-success": {
        "title": "Possible successful login inside a brute-force burst",
        "remediation": (
            "Inside the burst, one attempt was answered with a "
            "redirect - the pattern a correct password produces. "
            "Treat this as a possible account takeover until "
            "proven otherwise: force a password reset on the "
            "account, revoke its sessions, enable two-factor "
            "authentication, and review everything done under "
            "that account afterwards."
        ),
    },
}
