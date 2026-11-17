import sys
import unittest
from types import SimpleNamespace

# Ensure project root is in path for direct execution
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.tools.discovery.nikto_wrapper import NiktoWrapper  # noqa: E402


class TestNiktoWrapper(unittest.TestCase):
    def setUp(self):
        self.wrapper = NiktoWrapper(validate_binary=False)

    def test_build_command_default(self):
        cmd = self.wrapper._build_command("http://example.com", {})
        flattened = " ".join(cmd).lower()
        self.assertTrue("perl" in cmd[0].lower() or "nikto" in cmd[0].lower() or "cmd" == cmd[0].lower())
        self.assertTrue(any("nikto" in part.lower() for part in cmd))
        self.assertIn("json", flattened)
        self.assertIn("-output", flattened)

    def test_build_command_adds_maxtime_from_tool_timeout(self):
        cmd = self.wrapper._build_command("http://example.com", {"tool_timeout": 180, "timeout": 15})
        flattened = " ".join(cmd)

        self.assertIn("-maxtime", flattened)
        self.assertIn("150s", flattened)

    def test_parse_json_records(self):
        sample = {
            "host": "example",
            "vulnerabilities": [
                {
                    "msg": "Outdated Apache version 2.4.10",
                    "severity": "2",
                    "url": "http://example.com/",
                    "id": "OSVDB-123",
                },
                {
                    "msg": "X-Frame-Options header not present",
                    "severity": "1",
                    "url": "http://example.com/login",
                    "id": "OSVDB-456",
                },
            ],
        }
        findings = self.wrapper._parse_json_records(sample, "http://example.com")
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["detection_method"], "nikto")
        self.assertEqual(findings[0]["verification_status"], "needs_manual_verification")

    def test_merge_duplicates(self):
        findings = [
            {
                "title": "Default or Backup File Exposed",
                "risk_level": "medium",
                "description": "Nikto reported: Test at /a",
                "evidence": {"endpoint": "/a"},
            },
            {
                "title": "Default or Backup File Exposed",
                "risk_level": "medium",
                "description": "Nikto reported: Test at /a",
                "evidence": {"endpoint": "/b"},
            },
        ]
        merged = self.wrapper._merge_findings(findings)
        self.assertEqual(len(merged), 1)
        endpoints = merged[0]["evidence"].get("endpoints", [])
        self.assertEqual(len(endpoints), 2)

    def test_parse_text_output(self):
        raw = "+ /phpinfo.php exposes phpinfo()\n+ Header X-Frame-Options not set"
        findings = self.wrapper._parse_text_output(raw, "http://example.com")
        self.assertTrue(any(f["detection_method"] == "nikto" for f in findings))
        self.assertTrue(all(f["verification_status"] == "needs_manual_verification" for f in findings))

    def test_run_success_with_mock(self):
        sample_output = '{"vulnerabilities":[{"msg":"Outdated OpenSSL","severity":"3","url":"http://target"}]}'

        def fake_exec(cmd, timeout=300):
            return SimpleNamespace(stdout=sample_output, returncode=0)

        self.wrapper._execute_command = fake_exec  # type: ignore
        result = self.wrapper.run("http://target", {})
        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.findings), 1)

    def test_run_timeout_without_output_returns_failure(self):
        def fake_exec(cmd, timeout=300):
            return SimpleNamespace(stdout="", stderr="Command timed out after 120s", returncode=-1)

        self.wrapper._execute_command = fake_exec  # type: ignore
        result = self.wrapper.run("http://target", {"timeout": 15, "tool_timeout": 120})

        self.assertFalse(result.success)
        self.assertEqual(len(result.findings), 0)
        self.assertTrue(any("timed out" in err.lower() for err in result.errors))


if __name__ == "__main__":
    unittest.main()
