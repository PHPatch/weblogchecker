import gzip
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, "-m", "weblogchecker", *argv],
        capture_output=True, text=True, cwd=ROOT)


class CliTests(unittest.TestCase):
    def test_clean_log_exit_0(self):
        result = run_cli("analyze", str(FIXTURES / "clean_wp.log"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Findings: none", result.stdout)

    def test_dirty_log_exit_1(self):
        result = run_cli("analyze", str(FIXTURES / "shell_interaction.log"))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("webshell", result.stdout.lower())

    def test_missing_file_exit_2(self):
        result = run_cli("analyze", "/nonexistent/access.log")
        self.assertEqual(result.returncode, 2)

    def test_no_command_exit_2(self):
        result = run_cli()
        self.assertEqual(result.returncode, 2)

    def test_bad_since_exit_2(self):
        result = run_cli("analyze", str(FIXTURES / "clean_wp.log"),
                         "--since", "Oct 28 2026")
        self.assertEqual(result.returncode, 2)

    def test_json_output_valid(self):
        result = run_cli("analyze", str(FIXTURES / "bruteforce.log"),
                         "--format", "json")
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["tool"], "weblogchecker")
        self.assertEqual(report["summary"]["total_findings"], 3)

    def test_gzip_input(self):
        gz_path = FIXTURES / "shell_interaction.log.gz"
        with open(FIXTURES / "shell_interaction.log", "rb") as src, \
                gzip.open(gz_path, "wb") as dst:
            dst.write(src.read())
        try:
            result = run_cli("analyze", str(gz_path))
            self.assertEqual(result.returncode, 1, result.stderr)
        finally:
            gz_path.unlink()

    def test_stdin_input(self):
        with open(FIXTURES / "traversal_404.log", "rb") as fh:
            result = subprocess.run(
                [sys.executable, "-m", "weblogchecker", "analyze", "-"],
                input=fh.read(), capture_output=True, cwd=ROOT)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
