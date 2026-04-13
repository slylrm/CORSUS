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
        self.assertIn("nikto", cmd[0])
        self.assertIn("json", cmd)
        self.assertIn("-output", cmd)

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


if __name__ == "__main__":
    unittest.main()
