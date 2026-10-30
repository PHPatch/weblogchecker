import io
import json
import unittest
from datetime import date
from pathlib import Path

from weblogchecker.analyze import Analyzer, parse_line, parse_timestamp

FIXTURES = Path(__file__).parent / "fixtures"


def analyze_fixture(name, since=None):
    analyzer = Analyzer(since=since)
    with open(FIXTURES / name, encoding="utf-8") as fh:
        analyzer.run(fh)
    return analyzer.report(name, "test")


def classes(report):
    return {f["class"] for f in report["findings"]}


def by_class(report, class_id):
    return [f for f in report["findings"] if f["class"] == class_id]


class ParserTests(unittest.TestCase):
    def test_combined_line(self):
        entry = parse_line(
            '192.0.2.1 - frank [28/Oct/2026:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326 '
            '"http://www.example.com/start.html" '
            '"Mozilla/4.08 [en] (Win98; I ;Nav)"')
        self.assertIsNotNone(entry)
        self.assertEqual(entry["ip"], "192.0.2.1")
        self.assertEqual(entry["method"], "GET")
        self.assertEqual(entry["path"], "/apache_pb.gif")
        self.assertEqual(entry["status"], 200)
        self.assertEqual(entry["ts"].utcoffset().total_seconds(), -7 * 3600)

    def test_common_line_without_referer_ua(self):
        entry = parse_line(
            '192.0.2.1 - - [28/Oct/2026:13:55:36 +0000] '
            '"POST /submit.php?a=1 HTTP/1.1" 302 0')
        self.assertIsNotNone(entry)
        self.assertEqual(entry["method"], "POST")
        self.assertEqual(entry["path"], "/submit.php")
        self.assertEqual(entry["query"], "a=1")
        self.assertEqual(entry["ua"], "")

    def test_garbage_lines_rejected(self):
        self.assertIsNone(parse_line("this is not a log line"))
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line(
            '192.0.2.1 - - [99/Zzz/2026:13:55:36 +0000] '
            '"GET / HTTP/1.1" 200 1'))

    def test_timestamp_parsing(self):
        ts = parse_timestamp("01/Jan/2026:00:00:01 +0530")
        self.assertEqual((ts.year, ts.month, ts.day), (2026, 1, 1))
        self.assertEqual(ts.utcoffset().total_seconds(), 5.5 * 3600)
        self.assertIsNone(parse_timestamp("not a timestamp"))


class CleanFixtureTests(unittest.TestCase):
    """The false-positive discipline gate: a normal busy WordPress
    day (admin logins, plugin updates, cron, image uploads via
    wp-admin, Jetpack xmlrpc) must produce ZERO findings."""

    def test_clean_wordpress_log_has_zero_findings(self):
        report = analyze_fixture("clean_wp.log")
        self.assertEqual(report["findings"], [],
                         "clean fixture produced findings: %s"
                         % json.dumps(report["findings"], indent=1))
        self.assertEqual(report["summary"]["total_findings"], 0)

    def test_clean_fixture_all_lines_parsed(self):
        report = analyze_fixture("clean_wp.log")
        self.assertEqual(report["stats"]["entries_parsed"], 34)
        self.assertEqual(report["stats"]["lines_skipped"], 0)


class ShellInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_fixture("shell_interaction.log")

    def test_webshell_access_high_high(self):
        hits = by_class(self.report, "webshell-access")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertEqual(hits[0]["confidence"], "high")
        self.assertEqual(hits[0]["count"], 3)
        self.assertTrue(hits[0]["evidence"])
        self.assertIn("phpscan hunt", hits[0]["remediation"])

    def test_probes_are_low(self):
        probes = by_class(self.report, "webshell-probe")
        self.assertEqual(len(probes), 5)
        for probe in probes:
            self.assertEqual(probe["severity"], "low")
            self.assertEqual(probe["confidence"], "low")

    def test_exec_in_upload_dir(self):
        hits = by_class(self.report, "exec-in-upload-dir")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertEqual(hits[0]["confidence"], "high")

    def test_post_to_static(self):
        hits = by_class(self.report, "post-to-static")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["path"],
                         "/wp-content/uploads/2026/10/logo.jpg")

    def test_unit_shell_access(self):
        hits = by_class(self.report, "unit-shell-access")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertIn("CVE-2026-109618", hits[0]["remediation"])

    def test_dropper_access_medium(self):
        hits = by_class(self.report, "dropper-access")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "medium")


class BruteForceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_fixture("bruteforce.log")

    def test_bursts_flagged(self):
        bursts = by_class(self.report, "brute-force")
        self.assertEqual(len(bursts), 2)
        for burst in bursts:
            self.assertEqual(burst["severity"], "medium")

    def test_possible_success_flagged(self):
        hits = by_class(self.report, "brute-force-success")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["ip"], "203.0.113.99")
        self.assertEqual(hits[0]["severity"], "high")

    def test_no_other_findings(self):
        self.assertEqual(classes(self.report),
                         {"brute-force", "brute-force-success"})


class TraversalFixtureTests(unittest.TestCase):
    """Attempts that all failed must stay LOW - someone knocking
    is not someone inside."""

    @classmethod
    def setUpClass(cls):
        cls.report = analyze_fixture("traversal_404.log")

    def test_only_low_severity(self):
        for finding in self.report["findings"]:
            self.assertEqual(finding["severity"], "low", finding)

    def test_expected_classes(self):
        found = classes(self.report)
        self.assertIn("exploit-probe", found)
        self.assertIn("scanner-ua", found)
        self.assertIn("webshell-probe", found)

    def test_encoded_traversal_detected(self):
        probes = by_class(self.report, "exploit-probe")
        paths = {p["path"] for p in probes}
        self.assertIn("/download.php", paths)  # %2e%2e%2f encoded form
        self.assertIn("/assets/app.js", paths)  # long base64 token


class SinceFilterTests(unittest.TestCase):
    def test_since_skips_earlier_entries(self):
        lines = (
            '192.0.2.1 - - [27/Oct/2026:10:00:00 +0000] '
            '"GET /c99.php HTTP/1.1" 200 10 "-" "curl/8"\n'
            '192.0.2.1 - - [28/Oct/2026:10:00:00 +0000] '
            '"GET /r57.php HTTP/1.1" 200 10 "-" "curl/8"\n'
        )
        analyzer = Analyzer(since=date(2026, 10, 28))
        analyzer.run(io.StringIO(lines))
        report = analyzer.report("inline", "test")
        self.assertEqual(report["stats"]["entries_before_since"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["path"], "/r57.php")


class EvidenceTests(unittest.TestCase):
    def test_evidence_truncated(self):
        long_line = ('192.0.2.1 - - [28/Oct/2026:10:00:00 +0000] '
                     '"GET /c99.php?pad=%s HTTP/1.1" 200 10 "-" "x"'
                     % ("A" * 900))
        analyzer = Analyzer()
        analyzer.run(io.StringIO(long_line + "\n"))
        report = analyzer.report("inline", "test")
        evidence = report["findings"][0]["evidence"][0]
        self.assertLessEqual(len(evidence), 320)
        self.assertTrue(evidence.endswith("[truncated]"))


if __name__ == "__main__":
    unittest.main()
