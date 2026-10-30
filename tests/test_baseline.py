import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

from weblogchecker.analyze import (
    Analyzer, collect_baseline, executable_path_key, parse_line)

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, "-m", "weblogchecker", *argv],
        capture_output=True, text=True, cwd=ROOT)


def analyze_pair(suspect_name, baseline_name):
    with open(FIXTURES / baseline_name, encoding="utf-8") as fh:
        baseline_paths, _ = collect_baseline(fh)
    analyzer = Analyzer(baseline_paths=baseline_paths,
                        baseline_name=baseline_name)
    with open(FIXTURES / suspect_name, encoding="utf-8") as fh:
        analyzer.run(fh)
    return analyzer.report(suspect_name, "test")


def first_seen(report):
    return [f for f in report["findings"]
            if f["class"] == "first-seen-executable"]


class BaselineCollectionTests(unittest.TestCase):
    def test_collects_executable_paths_only(self):
        with open(FIXTURES / "baseline_wp.log", encoding="utf-8") as fh:
            paths, stats = collect_baseline(fh)
        self.assertIn("/wp-login.php", paths)
        self.assertIn("/wp-cron.php", paths)
        self.assertIn("/wp-admin/load-styles.php", paths)  # query split off
        self.assertNotIn("/", paths)
        self.assertEqual(len(paths), 8)
        self.assertEqual(stats["entries_parsed"], 10)

    def test_path_key_normalization(self):
        entry = parse_line(
            '192.0.2.1 - - [28/Oct/2026:10:00:00 +0000] '
            '"GET /WP-Admin/OPTIONS.php?x=1 HTTP/1.1" 200 1 "-" "x"')
        self.assertEqual(executable_path_key(entry),
                         "/wp-admin/options.php")
        entry = parse_line(
            '192.0.2.1 - - [28/Oct/2026:10:00:00 +0000] '
            '"GET /style.css HTTP/1.1" 200 1 "-" "x"')
        self.assertIsNone(executable_path_key(entry))

    def test_no_baseline_no_first_seen_findings(self):
        analyzer = Analyzer()
        with open(FIXTURES / "first_seen_shell.log",
                  encoding="utf-8") as fh:
            analyzer.run(fh)
        report = analyzer.report("x", "test")
        self.assertEqual(first_seen(report), [])
        self.assertIsNone(report["baseline"])


class FirstSeenShellTests(unittest.TestCase):
    """(a) A webshell-style first-seen executable in the suspect
    log - random name, upload directory, absent from the trusted
    baseline - is flagged with its stacked signals."""

    @classmethod
    def setUpClass(cls):
        cls.report = analyze_pair("first_seen_shell.log",
                                  "baseline_wp.log")

    def test_shell_flagged_with_all_signals(self):
        hits = first_seen(self.report)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["path"],
                         "/wp-content/uploads/2026/10/x7q2.php")
        self.assertEqual(hit["delta"], "NEW")
        self.assertEqual(hit["severity"], "high")
        self.assertEqual(hit["confidence"], "medium")
        self.assertEqual(hit["count"], 3)
        self.assertEqual(hit["ips"], ["198.51.100.66"])
        self.assertEqual(hit["first_seen"],
                         "2026-10-28T03:13:40+00:00")
        self.assertTrue(hit["evidence"])
        self.assertEqual(hit["signals"], {
            "success_response": True,
            "post_method": True,
            "no_referrer": True,
            "few_source_ips": True,
            "upload_directory": True,
        })
        self.assertIn("phpscan hunt", hit["remediation"])

    def test_baseline_metadata_in_report(self):
        self.assertEqual(self.report["baseline"]["executable_paths"], 8)
        self.assertEqual(self.report["baseline"]["log"],
                         "baseline_wp.log")


class BaselineMembershipTests(unittest.TestCase):
    """(c) An executable present in the baseline is never flagged
    as first-seen, no matter how it behaves in the suspect log."""

    def test_baseline_executables_not_flagged(self):
        report = analyze_pair("first_seen_shell.log", "baseline_wp.log")
        flagged = {f["path"] for f in first_seen(report)}
        for known in ("/wp-login.php", "/wp-cron.php",
                      "/wp-admin/admin-ajax.php"):
            self.assertNotIn(known, flagged)

    def test_baseline_path_with_shell_like_traffic_not_flagged(self):
        baseline = io.StringIO(
            '192.0.2.1 - - [20/Oct/2026:10:00:00 +0000] '
            '"GET /tools/run.php HTTP/1.1" 200 10 "-" "curl/8"\n')
        paths, _ = collect_baseline(baseline)
        suspect = io.StringIO(
            '198.51.100.66 - - [28/Oct/2026:10:00:00 +0000] '
            '"POST /tools/run.php HTTP/1.1" 200 10 "-" "curl/8"\n'
            '198.51.100.66 - - [28/Oct/2026:10:01:00 +0000] '
            '"POST /tools/run.php HTTP/1.1" 200 10 "-" "curl/8"\n')
        analyzer = Analyzer(baseline_paths=paths)
        analyzer.run(suspect)
        report = analyzer.report("inline", "test")
        self.assertEqual(first_seen(report), [])


class BaselineFalsePositiveGateTests(unittest.TestCase):
    """(b) THE GATE: a normal busy WordPress log pair - the later
    log adds only ordinary new paths behaving normally (an admin
    installing a plugin through wp-admin, a contact form posting
    to admin-post.php from many visitors, a new post) - yields
    ZERO medium/high findings across the whole report."""

    @classmethod
    def setUpClass(cls):
        cls.report = analyze_pair("baseline_pair_new.log",
                                  "baseline_pair_old.log")

    def test_zero_medium_or_high(self):
        offenders = [f for f in self.report["findings"]
                     if f["severity"] in ("medium", "high")]
        self.assertEqual(offenders, [],
                         "gate broken by: %s"
                         % json.dumps(offenders, indent=1))
        self.assertEqual(
            self.report["summary"]["by_severity"]["medium"], 0)
        self.assertEqual(
            self.report["summary"]["by_severity"]["high"], 0)

    def test_tracking_ran_and_stayed_low(self):
        hits = first_seen(self.report)
        self.assertTrue(hits, "expected low first-seen notes")
        for hit in hits:
            self.assertEqual(hit["severity"], "low", hit)
            self.assertEqual(hit["delta"], "NEW")

    def test_admin_introduced_install_capped_low(self):
        hits = {f["path"]: f for f in first_seen(self.report)}
        install = hits.get("/wp-admin/update.php")
        self.assertIsNotNone(install)
        self.assertEqual(install["severity"], "low")
        self.assertIn("wp-admin", install["detail"])


class BaselineSeverityDisciplineTests(unittest.TestCase):
    """First-seen alone never exceeds MED: escalation needs the
    stacked signals, and shape alone caps confidence at medium."""

    def _report_for(self, suspect_lines):
        baseline = io.StringIO(
            '192.0.2.1 - - [20/Oct/2026:10:00:00 +0000] '
            '"GET /index.php HTTP/1.1" 200 10 "-" "curl/8"\n')
        paths, _ = collect_baseline(baseline)
        analyzer = Analyzer(baseline_paths=paths)
        analyzer.run(io.StringIO(suspect_lines))
        return analyzer.report("inline", "test")

    def test_quiet_new_executable_is_low(self):
        # One browser GET with a page referrer from one of many
        # IPs across the file: only the success signal fires.
        report = self._report_for(
            '192.0.2.9 - - [28/Oct/2026:10:00:00 +0000] '
            '"GET /wp-content/plugins/akismet/akismet.php HTTP/1.1" '
            '200 10 "https://shop.example.com/" "Mozilla/5.0"\n'
            '192.0.2.10 - - [28/Oct/2026:10:01:00 +0000] '
            '"GET /wp-content/plugins/akismet/akismet.php HTTP/1.1" '
            '200 10 "https://shop.example.com/" "Mozilla/5.0"\n'
            '192.0.2.11 - - [28/Oct/2026:10:02:00 +0000] '
            '"GET /wp-content/plugins/akismet/akismet.php HTTP/1.1" '
            '200 10 "https://shop.example.com/" "Mozilla/5.0"\n')
        hits = first_seen(report)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "low")
        self.assertEqual(hits[0]["confidence"], "low")

    def test_three_signals_reach_medium_not_high(self):
        # POST + 2xx + few IPs, but with a referrer and outside an
        # upload directory: exactly three stacked signals.
        report = self._report_for(
            '198.51.100.66 - - [28/Oct/2026:10:00:00 +0000] '
            '"POST /misc/tool.php HTTP/1.1" 200 10 '
            '"https://shop.example.com/misc/" "curl/8"\n')
        hits = first_seen(report)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")
        self.assertEqual(hits[0]["confidence"], "medium")


class BaselineCliTests(unittest.TestCase):
    def test_cli_baseline_json(self):
        result = run_cli(
            "analyze", str(FIXTURES / "first_seen_shell.log"),
            "--baseline", str(FIXTURES / "baseline_wp.log"),
            "--format", "json")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        hits = [f for f in report["findings"]
                if f["class"] == "first-seen-executable"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["delta"], "NEW")
        self.assertEqual(report["baseline"]["executable_paths"], 8)

    def test_cli_baseline_pair_no_medium_high(self):
        # The gate pair may produce low first-seen notes, but no
        # medium/high findings anywhere in the report.
        result = run_cli(
            "analyze", str(FIXTURES / "baseline_pair_new.log"),
            "--baseline", str(FIXTURES / "baseline_pair_old.log"),
            "--format", "json")
        report = json.loads(result.stdout)
        self.assertEqual(
            report["summary"]["by_severity"]["medium"], 0)
        self.assertEqual(report["summary"]["by_severity"]["high"], 0)

    def test_cli_missing_baseline_exit_2(self):
        result = run_cli(
            "analyze", str(FIXTURES / "first_seen_shell.log"),
            "--baseline", "/nonexistent/old.log")
        self.assertEqual(result.returncode, 2)

    def test_cli_double_stdin_exit_2(self):
        result = run_cli("analyze", "-", "--baseline", "-")
        self.assertEqual(result.returncode, 2)

    def test_cli_text_shows_baseline_and_signals(self):
        result = run_cli(
            "analyze", str(FIXTURES / "first_seen_shell.log"),
            "--baseline", str(FIXTURES / "baseline_wp.log"))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Baseline:", result.stdout)
        self.assertIn("[NEW]", result.stdout)
        self.assertIn("Signals fired:", result.stdout)


if __name__ == "__main__":
    unittest.main()
