import sys
import unittest
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.tools.discovery.dir_scanner_wrapper import DirScannerWrapper  # noqa: E402


class TestDirScannerWrapper(unittest.TestCase):
    def setUp(self):
        self.wrapper = DirScannerWrapper(validate_binary=False)

    def test_build_command_defaults(self):
        cmd = self.wrapper._build_command("http://example.com", {})
        self.assertIn("gobuster", cmd[0])
        self.assertIn("-w", cmd)
        self.assertIn("-q", cmd)

    def test_parse_line_200(self):
        line = "/admin (Status: 200) [Size: 1234]"
        finding = self.wrapper._parse_line(line, "http://example.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["risk_level"], "info")
        self.assertEqual(finding["detection_method"], "dir_scanner")
        self.assertEqual(finding["verification_status"], "unverified")

    def test_parse_line_403(self):
        line = "/secret (Status: 403) [Size: 0]"
        finding = self.wrapper._parse_line(line, "http://example.com")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["risk_level"], "low")

    def test_parse_line_404_skipped(self):
        line = "/missing (Status: 404) [Size: 0]"
        finding = self.wrapper._parse_line(line, "http://example.com")
        self.assertIsNone(finding)

    def test_merge_findings(self):
        findings = [
            {"affected_url": "http://example.com/a", "risk_level": "info", "evidence": {"raw": "line1"}},
            {"affected_url": "http://example.com/a", "risk_level": "info", "evidence": {"raw": "line2"}},
        ]
        merged = self.wrapper._merge_findings(findings)
        self.assertEqual(len(merged), 1)
        self.assertIn("sources", merged[0]["evidence"])
        self.assertIn("line2", merged[0]["evidence"].get("raw", ""))

    def test_run_with_mock(self):
        sample = "/admin (Status: 200) [Size: 100]"

        def fake_exec(cmd, timeout=300):
            return SimpleNamespace(stdout=sample, returncode=0)

        self.wrapper._execute_command = fake_exec  # type: ignore
        result = self.wrapper.run("http://example.com", {})
        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main()
