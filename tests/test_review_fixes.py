"""Regression tests for the 2026-10-30 expert-review fixes
(L1-L4 and the section 3.3 hygiene items), plus the
second-pass review fix N4 (severity-aware findings cap)."""

import io
import json
import subprocess
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import weblogchecker.analyze as analyze_module
from weblogchecker import __version__
from weblogchecker.analyze import Analyzer, _BruteTracker
from weblogchecker.render import render_text

FIXTURES = Path(__file__).parent / "fixtures"

BASE = datetime(2026, 10, 28, 10, 0, 0, tzinfo=timezone.utc)


def entry(ip, ts, path="/wp-login.php", status=200, method="POST",
          referer="-", ua="curl/8"):
    return {
        "ip": ip, "ts": ts, "method": method,
        "target": path, "path": path, "query": "",
        "status": status, "referer": referer, "ua": ua,
        "line": "synthetic",
    }


def log_line(ip, ts, request, status, referer="-"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return ('%s - - [%s] "%s" %d 10 "%s" "curl/8"\n'
            % (ip, stamp, request, status, referer))


def analyze_lines(lines, baseline_paths=None):
    analyzer = Analyzer(baseline_paths=baseline_paths)
    analyzer.run(io.StringIO("".join(lines)))
    return analyzer, analyzer.report("inline", "test")


class BruteTrackerCounterTests(unittest.TestCase):
    """L1 semantics: the running counters must reproduce the
    old re-summed window exactly - eviction, the failure count
    a 302 is judged against, and the burst bookkeeping."""

    def test_window_counters_track_eviction(self):
        tracker = _BruteTracker()
        ip = "203.0.113.7"
        for i in range(5):
            tracker.feed(entry(ip, BASE + timedelta(seconds=i),
                               status=200))
        state = tracker._per_ip[ip]
        self.assertEqual(state["window_failures"], 5)
        self.assertEqual(state["window_302"], 0)
        # 605s later the whole first burst has left the window.
        tracker.feed(entry(ip, BASE + timedelta(seconds=605),
                           status=302))
        self.assertEqual(state["window_failures"], 0)
        self.assertEqual(state["window_302"], 1)
        self.assertEqual(len(state["window"]), 1)

    def test_possible_success_uses_prior_failures_only(self):
        tracker = _BruteTracker()
        ip = "203.0.113.8"
        # Four failures then a 302: below the success threshold.
        for i in range(4):
            tracker.feed(entry(ip, BASE + timedelta(seconds=i),
                               status=200))
        tracker.feed(entry(ip, BASE + timedelta(seconds=4),
                           status=302))
        self.assertIsNone(tracker._per_ip[ip]["possible_success"])
        # Fifth failure, then a 302: the 302 now follows >= 5
        # in-window failures and is flagged.
        tracker.feed(entry(ip, BASE + timedelta(seconds=5),
                           status=200))
        tracker.feed(entry(ip, BASE + timedelta(seconds=6),
                           status=302))
        self.assertIsNotNone(tracker._per_ip[ip]["possible_success"])

    def test_burst_findings_shape_unchanged(self):
        lines = []
        for i in range(25):
            lines.append(log_line(
                "203.0.113.9", BASE + timedelta(seconds=i),
                "POST /wp-login.php HTTP/1.1", 200))
        _, report = analyze_lines(lines)
        bursts = [f for f in report["findings"]
                  if f["class"] == "brute-force"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["count"], 25)
        self.assertIn("25 login POSTs in a 10-minute window",
                      bursts[0]["detail"])


class BruteTrackerScaleTests(unittest.TestCase):
    """L1 regression: 100k login POSTs from one IP must feed
    in well under the stated 5-second budget (the quadratic
    version needed ~80s for 40k). Parsing is outside the timed
    section - it is linear and not what regressed."""

    BUDGET_SECONDS = 5.0

    def test_100k_entries_one_ip_within_budget(self):
        entries = []
        for i in range(100_000):
            ts = BASE + timedelta(seconds=i)
            entries.append(entry("203.0.113.10", ts, status=200))
        tracker = _BruteTracker()
        start = time.perf_counter()
        for e in entries:
            tracker.feed(e)
        elapsed = time.perf_counter() - start
        self.assertLess(
            elapsed, self.BUDGET_SECONDS,
            "feeding 100k entries took %.2fs (budget %.0fs)"
            % (elapsed, self.BUDGET_SECONDS))
        state = tracker._per_ip["203.0.113.10"]
        self.assertEqual(state["total"], 100_000)
        # 1 POST/second: the 600s window holds 601 entries.
        self.assertEqual(state["max_window_posts"], 601)
        self.assertEqual(state["window_failures"],
                         len(state["window"]))


class NeverAnsweredRollupTests(unittest.TestCase):
    """L2: first-seen paths that never answered 2xx/3xx are
    not findings - they roll into one count."""

    BASELINE = {"/index.php"}

    def test_scanner_noise_rolls_up(self):
        lines = [log_line("203.0.113.20", BASE + timedelta(seconds=i),
                          "GET /probe-%d.php HTTP/1.1" % i, 404)
                 for i in range(50)]
        lines.append(log_line(
            "203.0.113.20", BASE + timedelta(seconds=60),
            "GET /real-new.php HTTP/1.1", 200))
        _, report = analyze_lines(lines, baseline_paths=self.BASELINE)
        hits = [f for f in report["findings"]
                if f["class"] == "first-seen-executable"]
        self.assertEqual([h["path"] for h in hits], ["/real-new.php"])
        self.assertEqual(
            report["baseline"]["probed_paths_never_existed"], 50)
        self.assertEqual(
            report["baseline"]["probed_requests_never_answered"], 50)

    def test_redirect_counts_as_answered(self):
        lines = [log_line("203.0.113.21", BASE,
                          "POST /moved.php HTTP/1.1", 302)]
        _, report = analyze_lines(lines, baseline_paths=self.BASELINE)
        hits = [f for f in report["findings"]
                if f["class"] == "first-seen-executable"]
        self.assertEqual([h["path"] for h in hits], ["/moved.php"])
        self.assertEqual(
            report["baseline"]["probed_paths_never_existed"], 0)

    def test_rollup_also_in_text_render(self):
        lines = [log_line("203.0.113.22", BASE,
                          "GET /ghost.php HTTP/1.1", 404)]
        _, report = analyze_lines(lines, baseline_paths=self.BASELINE)
        text = render_text(report)
        self.assertIn("1 probed paths never existed", text)


class TrackingCapTests(unittest.TestCase):
    """L3: tracked state is capped; overflow is counted and
    disclosed as findings_truncated."""

    def run_capped(self, lines, baseline_paths=None):
        with mock.patch.object(analyze_module, "MAX_TRACKED_KEYS", 5):
            return analyze_lines(lines, baseline_paths=baseline_paths)

    def test_findings_cap_disclosed(self):
        lines = []
        for i in range(12):
            lines.append(log_line(
                "203.0.113.%d" % i, BASE,
                "GET /c99.php HTTP/1.1", 200))
        _, report = self.run_capped(lines)
        self.assertTrue(report["findings_truncated"])
        self.assertGreater(
            report["stats"]["tracking_overflow"]["findings"], 0)
        self.assertTrue(any("truncated" in n
                            for n in report["notes"]))

    def test_brute_ip_cap_disclosed(self):
        lines = []
        for i in range(12):
            lines.append(log_line(
                "198.51.100.%d" % i, BASE,
                "POST /wp-login.php HTTP/1.1", 200))
        analyzer, report = self.run_capped(lines)
        self.assertEqual(len(analyzer._brute._per_ip), 5)
        self.assertGreater(
            report["stats"]["tracking_overflow"]["brute_force_ips"], 0)
        self.assertTrue(report["findings_truncated"])

    def test_first_seen_cap_disclosed(self):
        lines = [log_line("203.0.113.30", BASE + timedelta(seconds=i),
                          "GET /new-%d.php HTTP/1.1" % i, 200)
                 for i in range(12)]
        analyzer, report = self.run_capped(
            lines, baseline_paths={"/index.php"})
        self.assertEqual(len(analyzer._first_seen), 5)
        self.assertGreater(
            report["stats"]["tracking_overflow"]["first_seen_paths"],
            0)
        self.assertTrue(report["findings_truncated"])

    def test_under_cap_not_truncated(self):
        analyzer = Analyzer()
        with open(FIXTURES / "shell_interaction.log",
                  encoding="utf-8") as fh:
            analyzer.run(fh)
        report = analyzer.report("x", "test")
        self.assertFalse(report["findings_truncated"])
        self.assertEqual(
            report["stats"]["tracking_overflow"],
            {"findings": 0, "brute_force_ips": 0,
             "brute_force_target_paths": 0, "first_seen_paths": 0,
             "first_seen_ips": 0})


class ProxyBlindSpotTests(unittest.TestCase):
    """L4: a log whose requests come from 1-2 distinct IPs is
    CDN/proxy-shaped; the report must state that IP-based
    signals are unreliable there."""

    def _report(self, ips):
        lines = [log_line(ip, BASE + timedelta(seconds=n),
                          "GET /index.php HTTP/1.1", 200)
                 for n, ip in enumerate(ips)]
        _, report = analyze_lines(lines)
        return report

    def test_single_ip_note(self):
        report = self._report(["203.0.113.40"] * 5)
        notes = [n for n in report["notes"] if "Blind spot" in n]
        self.assertEqual(len(notes), 1)
        self.assertIn("brute-force", notes[0])
        self.assertIn("few source IPs", notes[0])
        self.assertIn("proxy", notes[0])

    def test_two_ip_note(self):
        report = self._report(
            ["203.0.113.40", "203.0.113.41"] * 3)
        self.assertTrue(any("Blind spot" in n
                            for n in report["notes"]))

    def test_many_ips_no_note(self):
        report = self._report(
            ["203.0.113.%d" % i for i in range(10)])
        self.assertFalse(any("Blind spot" in n
                             for n in report["notes"]))

    def test_note_in_text_render(self):
        report = self._report(["203.0.113.40"] * 3)
        self.assertIn("NOTE: Blind spot", render_text(report))


class SeverityAwareCapTests(unittest.TestCase):
    """N4: the findings cap is partitioned by severity, so a
    flood in one severity class cannot consume the capacity
    reserved for the others, and once anything is truncated
    the verdict itself says the results are incomplete."""

    def run_capped(self, lines, cap, baseline_paths=None):
        with mock.patch.object(analyze_module, "MAX_TRACKED_KEYS",
                               cap):
            return analyze_lines(lines,
                                 baseline_paths=baseline_paths)

    @staticmethod
    def junk_probes(count):
        # LOW findings: probes for a known shell filename, all
        # answered 404, each from a distinct IP - one finding
        # key per hit, the cheapest flood an attacker has.
        lines = []
        for i in range(count):
            ip = "203.%d.%d.%d" % ((i >> 16) & 255,
                                   (i >> 8) & 255, i & 255)
            lines.append(log_line(
                ip, BASE + timedelta(seconds=i),
                "GET /c99.php HTTP/1.1", 404))
        return lines

    def test_low_flood_cannot_displace_later_shell(self):
        # The second-pass reviewer's repro shape: cap lowered
        # to 200, 1,500 junk low findings, then one real shell
        # hit. Before the fix the shell finding was absent.
        lines = self.junk_probes(1500)
        lines.append(log_line(
            "198.51.100.9", BASE + timedelta(seconds=2000),
            "GET /shell.php?cmd=id HTTP/1.1", 200))
        analyzer, report = self.run_capped(lines, 200)
        shell = [f for f in report["findings"]
                 if f["path"] == "/shell.php"]
        self.assertEqual(len(shell), 1)
        self.assertEqual(shell[0]["severity"], "high")
        # The low partition at cap 200 is 45% = 90 keys; the
        # rest of the flood was refused and counted per class.
        self.assertEqual(analyzer._findings_by_severity["low"], 90)
        self.assertEqual(
            analyzer._overflow_by_severity["low"], 1410)
        self.assertTrue(report["findings_truncated"])
        self.assertGreater(
            report["stats"]["tracking_overflow"]["findings"], 0)
        # The headline verdict itself - and therefore the text
        # rendering built on it - says the results are
        # incomplete, not just a stats field.
        self.assertTrue(
            report["verdict"].startswith("INCOMPLETE RESULTS"))
        self.assertIn("INCOMPLETE RESULTS", render_text(report))
        self.assertTrue(any(
            "low 1410" in n for n in report["notes"]))

    def test_medium_flood_cannot_displace_high(self):
        # GETs of executables in an upload directory answered
        # 200 are medium findings; flood those well past the
        # medium partition, then a high shell hit must land.
        lines = []
        for i in range(400):
            ip = "198.%d.%d.%d" % ((i >> 16) & 255,
                                   (i >> 8) & 255, i & 255)
            lines.append(log_line(
                ip, BASE + timedelta(seconds=i),
                "GET /wp-content/uploads/j%d.php HTTP/1.1" % i,
                200))
        lines.append(log_line(
            "192.0.2.9", BASE + timedelta(seconds=1000),
            "GET /shell.php HTTP/1.1", 200))
        analyzer, report = self.run_capped(lines, 200)
        # The medium partition at cap 200 is 30% = 60 keys.
        self.assertEqual(
            analyzer._findings_by_severity["medium"], 60)
        self.assertGreater(
            analyzer._overflow_by_severity["medium"], 0)
        self.assertIn("/shell.php",
                      {f["path"] for f in report["findings"]})

    def test_severity_upgrade_moves_partition_never_blocked(self):
        # Fill the high partition (20% of cap 10 = 2 keys), then
        # admit a medium finding whose key a later POST upgrades
        # to high: the upgrade must land even with high full,
        # and the accounting must move with it.
        lines = [
            log_line("192.0.2.1", BASE,
                     "GET /c99.php HTTP/1.1", 200),
            log_line("192.0.2.2", BASE,
                     "GET /c99.php HTTP/1.1", 200),
            log_line("192.0.2.3", BASE,
                     "GET /wp-content/uploads/report.php HTTP/1.1",
                     200),
            log_line("192.0.2.3", BASE + timedelta(seconds=5),
                     "POST /wp-content/uploads/report.php HTTP/1.1",
                     200),
        ]
        analyzer, report = self.run_capped(lines, 10)
        self.assertEqual(analyzer._findings_by_severity["medium"], 0)
        self.assertEqual(analyzer._findings_by_severity["high"], 3)
        upgraded = [f for f in report["findings"]
                    if f["path"] == "/wp-content/uploads/report.php"]
        self.assertEqual(len(upgraded), 1)
        self.assertEqual(upgraded[0]["severity"], "high")

    def test_incomplete_verdict_without_findings(self):
        # Truncation in a non-findings class (first-seen path
        # tracking, all paths never answered -> no findings at
        # all): the "no indicators" verdict must still carry
        # the incompleteness in its own text.
        lines = [log_line("203.0.113.30",
                          BASE + timedelta(seconds=i),
                          "GET /new-%d.php HTTP/1.1" % i, 404)
                 for i in range(12)]
        _, report = self.run_capped(lines, 5,
                                    baseline_paths={"/index.php"})
        self.assertEqual(report["findings"], [])
        self.assertTrue(report["findings_truncated"])
        self.assertTrue(
            report["verdict"].startswith("INCOMPLETE RESULTS"))


class ReportContractTests(unittest.TestCase):
    """Family consistency: schema_version in the JSON report,
    and a working --version flag on the CLI."""

    def test_schema_version_present(self):
        _, report = analyze_lines([log_line(
            "203.0.113.1", BASE, "GET / HTTP/1.1", 200)])
        self.assertEqual(report["schema_version"], 1)
        # It survives the JSON round trip the CLI prints.
        self.assertEqual(
            json.loads(json.dumps(report))["schema_version"], 1)

    def test_version_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "weblogchecker", "--version"],
            capture_output=True, text=True,
            cwd=Path(__file__).parent.parent)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(__version__, result.stdout)


if __name__ == "__main__":
    unittest.main()
