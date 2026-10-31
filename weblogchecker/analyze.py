"""Streaming access-log analysis.

Parses Apache combined / common and nginx default (combined)
access logs line by line - the file is never loaded into memory,
so multi-GB logs are fine. Every detector emits findings with a
severity and a confidence; weblogchecker reports indicators, never
verdicts of compromise.
"""

import gzip
import re
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, unquote_plus

from . import indicators as ind

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

MAX_EVIDENCE_PER_FINDING = 5
MAX_LINE_CHARS = 300

LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?'
    r'(?:\s+.*)?$'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

CODE_EXEC_RE = re.compile(
    r"\b(eval|assert|system|passthru|shell_exec|create_function|"
    r"base64_decode|proc_open|popen)\s*\("
)
WRAPPER_RE = re.compile(r"(php|data|expect|phar)://", re.IGNORECASE)
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{240,}")
REQUEST_SPLIT_RE = re.compile(r"^([A-Z]{3,10}) (.*)$")
PROTO_RE = re.compile(r" HTTP/\d(?:\.\d)?$")

# Classes aggregated per IP only (their path is not meaningful).
PATHLESS_CLASSES = {"scanner-ua"}

BRUTE_WINDOW = timedelta(seconds=600)
BRUTE_MIN_POSTS = 20
BRUTE_MIN_FAILURES = 10
BRUTE_SUCCESS_MIN_PRIOR_FAILURES = 5

# Cap on tracked state keys (finding keys, per-IP state,
# first-seen paths, per-IP target paths). A hostile or simply
# huge log must not grow memory without bound; state past the
# cap is dropped, counted, and disclosed in the report as
# findings_truncated instead of silently vanishing.
MAX_TRACKED_KEYS = 100_000

# N4 (second-pass expert review): admission to the findings
# table is severity-aware. A single first-come cap lets a flood
# of low-signal findings (e.g. a botnet's shell probes, one key
# per source IP) consume every slot, so a real shell finding
# later in the log is refused - the exact evidence the tool
# exists to surface. Instead, the findings share of
# MAX_TRACKED_KEYS is partitioned by severity: each severity
# class may hold at most its share of keys, so one class's
# flood can never consume another class's capacity. At the
# default 100,000-key cap the partitions are: info 5,000 keys
# (5%), low 45,000 (45%), medium 30,000 (30%), high 20,000
# (20%). A late high-severity finding therefore always has
# its own 20,000-key partition available no matter how much
# low/medium noise preceded it. Severity upgrades of an
# already-admitted key are never blocked (they allocate no
# new state); the key's accounting simply moves to the higher
# class's partition.
SEVERITY_KEY_SHARES = {
    "info": 0.05,
    "low": 0.45,
    "medium": 0.30,
    "high": 0.20,
}


def _severity_key_limit(severity):
    """Finding-key budget for one severity class (N4).

    Reads MAX_TRACKED_KEYS at call time so the partitions
    scale with the cap (and so tests can lower the cap and
    exercise the partitions at small numbers).
    """
    return max(1, int(MAX_TRACKED_KEYS
                      * SEVERITY_KEY_SHARES[severity]))

# Baseline-diff (first-seen executable) scoring. "Few source IPs"
# is one of the stacked weak signals; the severity table built on
# the signal count lives in Analyzer._first_seen_findings.
FEW_IPS_MAX = 2


def parse_timestamp(text):
    """Parse '28/Oct/2026:13:55:36 +0000' without locale dependence."""
    try:
        date_part, tz_part = text.rsplit(" ", 1)
        day, month_name, rest = date_part.split("/", 2)
        year, hour, minute, second = rest.split(":")
        sign = 1 if tz_part.startswith("+") else -1
        offset = timedelta(hours=int(tz_part[1:3]),
                           minutes=int(tz_part[3:5])) * sign
        return datetime(int(year), MONTHS[month_name], int(day),
                        int(hour), int(minute), int(second),
                        tzinfo=timezone(offset))
    except (ValueError, KeyError, IndexError):
        return None


def parse_line(raw_line):
    """Parse one log line into an entry dict, or None if unparseable."""
    line = raw_line.rstrip("\r\n")
    if not line.strip():
        return None
    match = LOG_RE.match(line)
    if not match:
        return None
    ts = parse_timestamp(match.group("ts"))
    if ts is None:
        return None
    request = match.group("req").replace('\\"', '"')
    method, target = "", request
    req_match = REQUEST_SPLIT_RE.match(request)
    if req_match:
        method, rest = req_match.groups()
        proto = PROTO_RE.search(rest)
        target = rest[:proto.start()] if proto else rest
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""
    status_text = match.group("status")
    return {
        "ip": match.group("ip"),
        "ts": ts,
        "method": method,
        "target": target,
        "path": path,
        "query": query,
        "status": int(status_text) if status_text.isdigit() else None,
        "referer": match.group("ref") or "",
        "ua": match.group("ua") or "",
        "line": line,
    }


def _decode(text, plus=False):
    """URL-decode up to two passes (double-encoding is common in probes)."""
    if not text:
        return ""
    out = unquote_plus(text) if plus else unquote(text)
    if "%" in out:
        out = unquote_plus(out) if plus else unquote(out)
    return out


def _truncate(line):
    clean = "".join(ch if ch.isprintable() else "?" for ch in line)
    if len(clean) > MAX_LINE_CHARS:
        return clean[:MAX_LINE_CHARS] + " ...[truncated]"
    return clean


def _success(status):
    return status is not None and 200 <= status < 400


def executable_path_key(entry):
    """Normalized identity of an executable path in an entry.

    Uses the same normalization the detectors use (URL-decoded,
    lower-cased; the parser has already split the query string
    off), so a file is the same file in the baseline and in the
    analyzed log regardless of casing or encoding. Returns None
    for non-executable paths.
    """
    path = _decode(entry["path"]).lower()
    if path.endswith(ind.EXECUTABLE_EXTS):
        return path
    return None


def collect_baseline(stream):
    """Stream a trusted baseline log and collect its executable paths.

    Returns (paths, stats): the set of normalized executable paths
    the baseline contains, and line accounting in the same shape
    as the analyzer's stats.
    """
    paths = set()
    stats = {"lines_read": 0, "entries_parsed": 0, "lines_skipped": 0}
    for raw in stream:
        stats["lines_read"] += 1
        entry = parse_line(raw)
        if entry is None:
            if raw.strip():
                stats["lines_skipped"] += 1
            continue
        stats["entries_parsed"] += 1
        key = executable_path_key(entry)
        if key is not None:
            paths.add(key)
    return paths, stats


class _BruteTracker:
    """Streaming sliding-window tracker for login POST bursts.

    The window's failure/redirect counts are running counters
    maintained on append/popleft, so feeding an entry is O(1).
    (An earlier version re-summed the whole window per entry -
    quadratic in the size of a burst, i.e. slowest exactly on
    the botnet-scale login floods this tracker exists for.)
    """

    def __init__(self):
        self._per_ip = {}
        # Feeds dropped because a tracked-state cap was reached:
        # new IPs past MAX_TRACKED_KEYS, and target paths past
        # the cap on an already-tracked IP.
        self.overflow_ips = 0
        self.overflow_target_paths = 0

    def feed(self, entry):
        ip = entry["ip"]
        state = self._per_ip.get(ip)
        if state is None:
            if len(self._per_ip) >= MAX_TRACKED_KEYS:
                self.overflow_ips += 1
                return
            state = {
                "window": deque(),
                "window_failures": 0,
                "window_302": 0,
                "total": 0,
                "target_paths": set(),
                "max_window_posts": 0,
                "max_window_failures": 0,
                "burst_first": None,
                "burst_last": None,
                "possible_success": None,
                "evidence": [],
            }
            self._per_ip[ip] = state
        ts = entry["ts"]
        status = entry["status"]
        window = state["window"]
        window.append((ts, status))
        if status == 302:
            state["window_302"] += 1
        else:
            state["window_failures"] += 1
        while window and ts - window[0][0] > BRUTE_WINDOW:
            _, evicted_status = window.popleft()
            if evicted_status == 302:
                state["window_302"] -= 1
            else:
                state["window_failures"] -= 1
        if (status == 302
                and state["window_failures"]
                >= BRUTE_SUCCESS_MIN_PRIOR_FAILURES
                and state["possible_success"] is None):
            # window_failures counts the non-302 entries still in
            # the window; this entry is a 302, so they are all
            # prior to it.
            state["possible_success"] = entry
        posts = len(window)
        failures = state["window_failures"]
        state["total"] += 1
        if entry["path"] not in state["target_paths"]:
            if len(state["target_paths"]) >= MAX_TRACKED_KEYS:
                self.overflow_target_paths += 1
            else:
                state["target_paths"].add(entry["path"])
        if posts > state["max_window_posts"]:
            state["max_window_posts"] = posts
            state["max_window_failures"] = failures
        if posts >= BRUTE_MIN_POSTS and failures >= BRUTE_MIN_FAILURES:
            if state["burst_first"] is None:
                state["burst_first"] = window[0][0]
            state["burst_last"] = ts
        if len(state["evidence"]) < 3:
            state["evidence"].append(_truncate(entry["line"]))

    def findings(self):
        out = []
        for ip, state in self._per_ip.items():
            if state["burst_first"] is None:
                continue
            evidence = list(state["evidence"])
            success = state["possible_success"]
            if success is not None:
                evidence.append(_truncate(success["line"]))
            paths = ", ".join(sorted(state["target_paths"]))
            out.append({
                "class": "brute-force", "severity": "medium",
                "confidence": "medium", "ip": ip, "path": paths,
                "count": state["total"],
                "first_seen": state["burst_first"],
                "last_seen": state["burst_last"] or state["burst_first"],
                "evidence": evidence,
                "detail": ("%d login POSTs in a 10-minute window "
                           "(%d not answered with a redirect)"
                           % (state["max_window_posts"],
                              state["max_window_failures"])),
            })
            if success is not None:
                out.append({
                    "class": "brute-force-success", "severity": "high",
                    "confidence": "medium", "ip": ip, "path": paths,
                    "count": 1,
                    "first_seen": success["ts"],
                    "last_seen": success["ts"],
                    "evidence": [_truncate(success["line"])],
                    "detail": ("a login POST answered 302 after at "
                               "least %d failed attempts in the same "
                               "burst" % BRUTE_SUCCESS_MIN_PRIOR_FAILURES),
                })
        return out


class Analyzer:
    def __init__(self, since=None, baseline_paths=None,
                 baseline_name=None):
        self.since = since  # a datetime.date or None
        # Normalized executable paths seen in a trusted baseline
        # log, or None when no baseline was supplied - first-seen
        # tracking is then off entirely and analysis behaves
        # exactly as it did before the baseline feature existed.
        self.baseline_paths = baseline_paths
        self.baseline_name = baseline_name
        self._first_seen = {}
        # Tracked-state cap accounting: keys dropped because a
        # cap (MAX_TRACKED_KEYS) was reached. Any nonzero count
        # flips findings_truncated on in the report.
        self._overflow = {
            "findings": 0,
            "first_seen_paths": 0,
            "first_seen_ips": 0,
        }
        # N4: findings keys held per severity class (the key's
        # CURRENT severity - an upgrade moves the count), and
        # finding keys refused per severity class. Admission is
        # per-class against SEVERITY_KEY_SHARES partitions of
        # MAX_TRACKED_KEYS, never first-come across classes.
        self._findings_by_severity = {name: 0 for name in
                                      SEVERITY_RANK}
        self._overflow_by_severity = {name: 0 for name in
                                      SEVERITY_RANK}
        # Distinct source IPs among analyzed entries - the input
        # to the behind-a-proxy blind-spot disclosure. Capped at
        # MAX_TRACKED_KEYS entries; past that the count is far
        # above the 1-2 IP proxy signature anyway.
        self._source_ips = set()
        # First-seen paths that never answered 2xx/3xx, rolled
        # into one count by _first_seen_findings (see there).
        self._never_answered = {"paths": 0, "requests": 0}
        self.stats = {
            "lines_read": 0,
            "entries_parsed": 0,
            "lines_skipped": 0,
            "entries_before_since": 0,
            "first_entry": None,
            "last_entry": None,
        }
        self._findings = {}
        self._brute = _BruteTracker()

    # -- aggregation -------------------------------------------------
    def _add(self, class_id, severity, confidence, entry, detail=""):
        path_key = "" if class_id in PATHLESS_CLASSES else entry["path"]
        key = (class_id, entry["ip"], path_key)
        finding = self._findings.get(key)
        if finding is None:
            # N4: admission is checked against the incoming
            # severity's own partition of the cap, so a flood
            # in one severity class cannot starve the others.
            if self._findings_by_severity[severity] \
                    >= _severity_key_limit(severity):
                self._overflow["findings"] += 1
                self._overflow_by_severity[severity] += 1
                return
            finding = {
                "class": class_id, "severity": severity,
                "confidence": confidence, "ip": entry["ip"],
                "path": path_key, "count": 0,
                "first_seen": entry["ts"], "last_seen": entry["ts"],
                "evidence": [], "detail": detail,
            }
            self._findings[key] = finding
            self._findings_by_severity[severity] += 1
        finding["count"] += 1
        if entry["ts"] < finding["first_seen"]:
            finding["first_seen"] = entry["ts"]
        if entry["ts"] > finding["last_seen"]:
            finding["last_seen"] = entry["ts"]
        if SEVERITY_RANK[severity] > SEVERITY_RANK[finding["severity"]]:
            # The key moves to the higher severity's partition;
            # upgrades are never refused (no new state).
            self._findings_by_severity[finding["severity"]] -= 1
            self._findings_by_severity[severity] += 1
            finding["severity"] = severity
            if detail:
                finding["detail"] = detail
        if CONFIDENCE_RANK[confidence] > CONFIDENCE_RANK[finding["confidence"]]:
            finding["confidence"] = confidence
        if detail and not finding["detail"]:
            finding["detail"] = detail
        if len(finding["evidence"]) < MAX_EVIDENCE_PER_FINDING:
            finding["evidence"].append(_truncate(entry["line"]))

    # -- detectors ---------------------------------------------------
    def _detect(self, entry):
        path = entry["path"]
        decoded_path = _decode(path)
        lower_path = decoded_path.lower()
        basename = lower_path.rsplit("/", 1)[-1]
        status = entry["status"]
        ok = _success(status)
        method = entry["method"]

        # Known webshell filenames.
        if basename in ind.UNIT_TEST_SHELL_PATHS:
            if ok:
                self._add("unit-shell-access", "high", "high", entry,
                          "eval-stdin.php answered %s" % status)
            else:
                self._add("webshell-probe", "low", "low", entry,
                          "eval-stdin.php probed, status %s" % status)
        elif basename in ind.SHELL_NAMES_CANONICAL:
            if ok:
                self._add("webshell-access", "high", "high", entry,
                          "%s answered %s" % (basename, status))
            else:
                self._add("webshell-probe", "low", "low", entry,
                          "%s probed, status %s" % (basename, status))
        elif basename in ind.SHELL_NAMES_GENERIC:
            if ok:
                self._add("generic-shell-access", "high", "medium", entry,
                          "%s answered %s" % (basename, status))
            else:
                self._add("webshell-probe", "low", "low", entry,
                          "%s probed, status %s" % (basename, status))
        elif basename in ind.SHELL_NAMES_DROPPER:
            if ok:
                self._add("dropper-access", "medium", "low", entry,
                          "%s answered %s" % (basename, status))

        # Executable inside an upload / data directory.
        if lower_path.endswith(ind.EXECUTABLE_EXTS) and any(
                marker in lower_path for marker in ind.UPLOAD_DIR_MARKERS):
            if ok and method == "POST":
                self._add("exec-in-upload-dir", "high", "high", entry,
                          "POST to executable in a data directory, "
                          "status %s" % status)
            elif ok:
                self._add("exec-in-upload-dir", "medium", "medium", entry,
                          "executable in a data directory answered "
                          "%s" % status)
            elif method == "POST":
                self._add("upload-exec-probe", "low", "low", entry,
                          "POST to executable in a data directory, "
                          "status %s" % status)

        # POST/PUT to a static file.
        if method in ("POST", "PUT") and ok and \
                lower_path.endswith(ind.STATIC_EXTS):
            self._add("post-to-static", "high", "medium", entry,
                      "%s to a static file answered %s" % (method, status))

        # Exploitation patterns in the URI.
        decoded_query = _decode(entry["query"], plus=True)
        haystack = decoded_path + "?" + decoded_query
        pattern = None
        if "../" in haystack or "..\\" in haystack:
            pattern = "path traversal sequence"
        elif "/etc/passwd" in haystack:
            pattern = "attempt to read /etc/passwd"
        elif WRAPPER_RE.search(haystack):
            pattern = "stream-wrapper (php:// / data:// / expect://) reference"
        elif CODE_EXEC_RE.search(haystack):
            pattern = "code-execution keyword in the URI"
        elif LONG_TOKEN_RE.search(entry["query"] or ""):
            pattern = "very long base64-style token in the query string"
        if pattern is not None:
            if ok:
                self._add("exploit-success", "high", "medium", entry,
                          pattern + ", answered %s" % status)
            else:
                self._add("exploit-probe", "low", "low", entry,
                          pattern + ", status %s" % status)

        # Self-identified scanner user-agents.
        ua_lower = entry["ua"].lower()
        for fingerprint in ind.SCANNER_USER_AGENTS:
            if fingerprint in ua_lower:
                self._add("scanner-ua", "low", "low", entry,
                          "user-agent identifies as %s" % fingerprint)
                break

        # Login brute force (evaluated after the stream ends).
        if method == "POST" and basename in ind.LOGIN_BASENAMES:
            self._brute.feed(entry)

    # -- baseline diff ------------------------------------------------
    def _track_first_seen(self, entry):
        """Aggregate requests to executables absent from the baseline.

        Only runs when a baseline was supplied. An executable that
        appears in the baseline is never tracked, so it can never
        be reported as first-seen.
        """
        if self.baseline_paths is None:
            return
        key = executable_path_key(entry)
        if key is None or key in self.baseline_paths:
            return
        agg = self._first_seen.get(key)
        if agg is None:
            if len(self._first_seen) >= MAX_TRACKED_KEYS:
                self._overflow["first_seen_paths"] += 1
                return
            agg = {
                "count": 0, "first_seen": entry["ts"],
                "last_seen": entry["ts"], "success": 0, "posts": 0,
                "no_referrer": 0, "ips": Counter(),
                "first_referer": entry["referer"],
                "evidence": [],
            }
            self._first_seen[key] = agg
        agg["count"] += 1
        if entry["ts"] < agg["first_seen"]:
            agg["first_seen"] = entry["ts"]
            agg["first_referer"] = entry["referer"]
        if entry["ts"] > agg["last_seen"]:
            agg["last_seen"] = entry["ts"]
        if _success(entry["status"]):
            agg["success"] += 1
        if entry["method"] in ("POST", "PUT"):
            agg["posts"] += 1
        if entry["referer"] in ("", "-"):
            agg["no_referrer"] += 1
        if entry["ip"] not in agg["ips"] \
                and len(agg["ips"]) >= MAX_TRACKED_KEYS:
            self._overflow["first_seen_ips"] += 1
        else:
            agg["ips"][entry["ip"]] += 1
        if len(agg["evidence"]) < MAX_EVIDENCE_PER_FINDING:
            agg["evidence"].append(_truncate(entry["line"]))

    def _first_seen_findings(self):
        """Score first-seen executables on stacked weak signals.

        Severity discipline (the honesty contract): first-seen on
        its own is a LOW note. Climbing to medium takes three
        stacked signals, to high takes four or more - and a path
        whose first hit arrived from a wp-admin page is treated
        as admin-introduced (plugin install, core update): capped
        at low, and dropped entirely when its signal stack is
        thin, because ordinary admin work must not read as an
        incident. Confidence never exceeds medium: the signals
        are circumstantial by construction.

        A path that never answered 2xx/3xx is not reported at
        all: a file that only ever drew 404s cannot be a planted
        shell - it evidently is not there. Scanner sweeps probe
        thousands of such paths, so they are rolled into a
        single count (report -> baseline ->
        probed_paths_never_existed) instead of one finding each.
        """
        out = []
        self._never_answered = {"paths": 0, "requests": 0}
        for path in sorted(self._first_seen):
            agg = self._first_seen[path]
            if agg["success"] == 0:
                self._never_answered["paths"] += 1
                self._never_answered["requests"] += agg["count"]
                continue
            signals = {
                "success_response": agg["success"] > 0,
                "post_method": agg["posts"] > 0,
                "no_referrer": agg["no_referrer"] * 2 >= agg["count"],
                "few_source_ips": len(agg["ips"]) <= FEW_IPS_MAX,
                "upload_directory": any(
                    marker in path for marker in ind.UPLOAD_DIR_MARKERS),
            }
            stacked = sum(1 for fired in signals.values() if fired)
            admin_introduced = "/wp-admin/" in agg["first_referer"]
            if admin_introduced and stacked <= 2:
                continue
            if stacked <= 2:
                severity, confidence = "low", "low"
            elif stacked == 3:
                severity, confidence = "medium", "medium"
            else:
                severity, confidence = "high", "medium"
            notes = []
            if admin_introduced:
                severity = "low"
                notes.append(
                    "its first hit arrived from a wp-admin page, so "
                    "it looks admin-introduced and is capped at low")
            fired = [name for name, on in signals.items() if on]
            detail = (
                "absent from the baseline log; %d request(s) from "
                "%d IP(s), %d answered 2xx/3xx, %d POST/PUT, %d "
                "without a referrer. Signals fired (%d of 5): %s."
                % (agg["count"], len(agg["ips"]), agg["success"],
                   agg["posts"], agg["no_referrer"], stacked,
                   ", ".join(fired) if fired else "none"))
            if notes:
                detail += " Note: " + "; ".join(notes) + "."
            out.append({
                "class": "first-seen-executable",
                "delta": "NEW",
                "severity": severity, "confidence": confidence,
                "ip": agg["ips"].most_common(1)[0][0],
                "ips": sorted(agg["ips"]),
                "path": path, "count": agg["count"],
                "first_seen": agg["first_seen"],
                "last_seen": agg["last_seen"],
                "evidence": list(agg["evidence"]),
                "detail": detail,
                "signals": signals,
            })
        return out

    # -- main loop ---------------------------------------------------
    def run(self, stream):
        for raw in stream:
            self.stats["lines_read"] += 1
            entry = parse_line(raw)
            if entry is None:
                if raw.strip():
                    self.stats["lines_skipped"] += 1
                continue
            self.stats["entries_parsed"] += 1
            if self.since is not None and entry["ts"].date() < self.since:
                self.stats["entries_before_since"] += 1
                continue
            if self.stats["first_entry"] is None or \
                    entry["ts"] < self.stats["first_entry"]:
                self.stats["first_entry"] = entry["ts"]
            if self.stats["last_entry"] is None or \
                    entry["ts"] > self.stats["last_entry"]:
                self.stats["last_entry"] = entry["ts"]
            if len(self._source_ips) < MAX_TRACKED_KEYS:
                self._source_ips.add(entry["ip"])
            self._detect(entry)
            self._track_first_seen(entry)
        return self

    def report(self, source_name, version):
        findings = list(self._findings.values())
        for brute_finding in self._brute.findings():
            brute_finding.setdefault("evidence", [])
            findings.append(brute_finding)
        findings.extend(self._first_seen_findings())
        for finding in findings:
            info = ind.CLASS_INFO[finding["class"]]
            finding["title"] = info["title"]
            finding["remediation"] = info["remediation"]
            finding["first_seen"] = finding["first_seen"].isoformat()
            finding["last_seen"] = finding["last_seen"].isoformat()
        findings.sort(key=lambda f: (
            -SEVERITY_RANK[f["severity"]],
            -CONFIDENCE_RANK[f["confidence"]],
            -f["count"],
            f["first_seen"],
        ))

        incidents = {}
        for finding in findings:
            key = (finding["ip"], finding["path"])
            incident = incidents.get(key)
            if incident is None:
                incident = {
                    "ip": finding["ip"], "path": finding["path"],
                    "classes": [], "severity": finding["severity"],
                    "requests": 0,
                    "first_seen": finding["first_seen"],
                    "last_seen": finding["last_seen"],
                }
                incidents[key] = incident
            if finding["class"] not in incident["classes"]:
                incident["classes"].append(finding["class"])
            if SEVERITY_RANK[finding["severity"]] > \
                    SEVERITY_RANK[incident["severity"]]:
                incident["severity"] = finding["severity"]
            incident["requests"] += finding["count"]
            incident["first_seen"] = min(incident["first_seen"],
                                         finding["first_seen"])
            incident["last_seen"] = max(incident["last_seen"],
                                        finding["last_seen"])
        incident_list = sorted(
            incidents.values(),
            key=lambda i: (-SEVERITY_RANK[i["severity"]], i["first_seen"]))

        by_severity = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            by_severity[finding["severity"]] += 1

        stats = dict(self.stats)
        for key in ("first_entry", "last_entry"):
            stats[key] = stats[key].isoformat() if stats[key] else None
        tracking_overflow = {
            "findings": self._overflow["findings"],
            "brute_force_ips": self._brute.overflow_ips,
            "brute_force_target_paths":
                self._brute.overflow_target_paths,
            "first_seen_paths": self._overflow["first_seen_paths"],
            "first_seen_ips": self._overflow["first_seen_ips"],
        }
        stats["tracking_overflow"] = tracking_overflow
        findings_truncated = any(tracking_overflow.values())

        baseline_info = None
        if self.baseline_paths is not None:
            baseline_info = {
                "log": self.baseline_name,
                "executable_paths": len(self.baseline_paths),
                "probed_paths_never_existed":
                    self._never_answered["paths"],
                "probed_requests_never_answered":
                    self._never_answered["requests"],
            }

        notes = []
        if 1 <= len(self._source_ips) <= FEW_IPS_MAX:
            notes.append(
                "Blind spot: every analyzed request carries one "
                "of only %d source IP(s) (%s) - the signature of "
                "a CDN or reverse proxy in front of the origin. "
                "In that setup the logged IP is the proxy's, not "
                "the client's, so IP-based signals are unreliable "
                "and must be treated as disabled: per-IP "
                "brute-force detection cannot separate one "
                "attacker from all visitors sharing the proxy, "
                "and the first-seen 'few source IPs' signal "
                "fires for everything. For IP attribution, "
                "analyze the proxy/CDN log or a log format that "
                "records the real client IP."
                % (len(self._source_ips),
                   ", ".join(sorted(self._source_ips))))
        if findings_truncated:
            dropped = ", ".join(
                "%s %d" % (name,
                           self._overflow_by_severity[name])
                for name in ("high", "medium", "low", "info")
                if self._overflow_by_severity[name])
            notes.append(
                "Findings truncated: tracked state hit the "
                "%d-key cap while reading this log, so some "
                "findings/state were dropped (see "
                "stats.tracking_overflow for counts%s). What is "
                "reported below is a lower bound, not the full "
                "picture."
                % (MAX_TRACKED_KEYS,
                   "; findings dropped by severity: " + dropped
                   if dropped else ""))

        if findings:
            verdict = (
                "Indicators found. These are leads for investigation, "
                "not proof of compromise: work through the findings "
                "in severity order and confirm or clear each one "
                "against the files on disk."
            )
        else:
            verdict = (
                "No indicators found in the analyzed window. That "
                "does not prove the site is clean - only that none "
                "of the patterns weblogchecker checks appear in this log."
            )
        if findings_truncated:
            # N4: the headline itself must carry the
            # incompleteness - a stats field and a NOTE are too
            # easy to miss when the verdict is quoted on its own.
            verdict = (
                "INCOMPLETE RESULTS - " + verdict + " Tracked "
                "state hit its key caps while reading this log, "
                "so some findings were dropped: what is reported "
                "here is a lower bound, not the full picture."
            )

        return {
            "tool": "weblogchecker",
            "schema_version": 1,
            "version": version,
            "log": source_name,
            "baseline": baseline_info,
            "since": self.since.isoformat() if self.since else None,
            "stats": stats,
            "findings_truncated": findings_truncated,
            "notes": notes,
            "summary": {
                "total_findings": len(findings),
                "by_severity": by_severity,
                "ips_flagged": len({f["ip"] for f in findings}),
                "incidents": len(incident_list),
            },
            "verdict": verdict,
            "findings": findings,
            "incidents": incident_list,
        }


def open_log(path):
    """Open a log file (plain or .gz) as a text stream."""
    if path == "-":
        import sys
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")
