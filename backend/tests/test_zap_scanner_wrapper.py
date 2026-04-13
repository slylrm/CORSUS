import sys
import unittest
from unittest.mock import MagicMock
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.tools.discovery.zap_scanner_wrapper import ZapScannerWrapper  # noqa: E402
from app.tools.base import RiskLevel  # noqa: E402


class TestZapScannerWrapper(unittest.TestCase):
    def setUp(self):
        self.wrapper = ZapScannerWrapper(validate_binary=False)
        self.wrapper.session = MagicMock()

    def _mock_get(self, responses):
        def side_effect(url, params=None, timeout=30):
            data = responses.pop(0)
            resp = MagicMock()
            resp.json.return_value = data
            resp.raise_for_status.return_value = None
            return resp
        self.wrapper.session.get.side_effect = side_effect

    def test_risk_mapping(self):
        self.assertEqual(self.wrapper._map_risk("1"), RiskLevel.MEDIUM)
        self.assertEqual(self.wrapper._map_risk("2"), RiskLevel.HIGH)
        self.assertEqual(self.wrapper._map_risk("3"), RiskLevel.CRITICAL)
        self.assertIsNone(self.wrapper._map_risk("0"))

    def test_confidence(self):
        self.assertGreater(self.wrapper._confidence(3, True, False), 0.8)
        self.assertGreater(self.wrapper._confidence(1, False, True), 0.6)

    def test_alerts_to_findings_merge(self):
        alerts = [
            {"alert": "XSS", "risk": "2", "url": "http://t/a", "param": "q", "evidence": "ev1", "confidence": "2"},
            {"alert": "XSS", "risk": "2", "url": "http://t/a", "param": "q", "evidence": "ev2", "confidence": "2"},
        ]
        findings = self.wrapper._alerts_to_findings(alerts, active=False)
        self.assertEqual(len(findings), 1)
        ev = findings[0]["evidence"].get("evidence", "")
        self.assertIn("ev1", ev)
        self.assertIn("ev2", ev)

    def test_run_passive_mock(self):
        responses = [
            {"contextList": []},  # context list
            {},  # newContext
            {},  # includeInContext
            {"context": [{"id": "1"}]},  # context view
            {},  # accessUrl (none)
            {},  # spider scan
            {"status": "100"},  # spider status
            {"recordsToScan": "0"},  # passive done
            {"alerts": [{"alert": "Test", "risk": "2", "url": "http://t", "confidence": "2"}]},
        ]
        self._mock_get(responses)
        result = self.wrapper.run("http://t", {"active_scan": False})
        self.assertTrue(result.success)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]["detection_method"], "owasp_zap")


if __name__ == "__main__":
    unittest.main()
