import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path

# Ensure project root is in path for direct execution
sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.tools.injection.wapiti_wrapper import WapitiWrapper  # noqa: E402


class TestWapitiWrapper(unittest.TestCase):
    def _make_temp_dir(self) -> Path:
        root = Path(__file__).resolve().parents[2] / ".tmp" / "test-work"
        root.mkdir(parents=True, exist_ok=True)
        case_dir = root / f"case-{uuid.uuid4().hex}"
        case_dir.mkdir(parents=True, exist_ok=False)
        return case_dir

    def test_build_command_uses_python_for_script_path(self):
        temp_dir = self._make_temp_dir()
        try:
            script_path = temp_dir / "wapiti"
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            wrapper = WapitiWrapper(
                config={"path": str(script_path), "python_path": sys.executable},
                validate_binary=False,
            )
            output_file = temp_dir / "report.json"

            command = wrapper._build_command("https://example.com", {"max_scan_time": 5}, output_file)

            self.assertEqual(command[0], sys.executable)
            self.assertEqual(command[1], "-X")
            self.assertEqual(command[2], "utf8")
            self.assertEqual(command[3], str(script_path))
            self.assertIn("--max-scan-time", command)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_parse_json_output_builds_findings(self):
        report = {
            "classifications": {
                "sql": {
                    "title": "SQL Injection",
                    "desc": "Injection point found",
                    "sol": "Use parameterized queries",
                }
            },
            "vulnerabilities": {
                "sql": [
                    {
                        "path": "https://example.com/search?q=test",
                        "method": "GET",
                        "parameter": "q",
                        "level": 3,
                        "info": "payload triggered",
                    }
                ]
            },
        }

        temp_dir = self._make_temp_dir()
        try:
            report_file = temp_dir / "wapiti.json"
            report_file.write_text(json.dumps(report), encoding="utf-8")

            wrapper = WapitiWrapper(config={"path": "wapiti"}, validate_binary=False)
            findings = wrapper.parse_json_output(report_file)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].title, "SQL Injection")
            self.assertEqual(findings[0].risk_level.value, "high")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
