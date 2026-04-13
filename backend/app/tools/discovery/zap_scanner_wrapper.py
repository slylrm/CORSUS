"""
ZapScannerWrapper - OWASP ZAP integration for ScannerEngine/ToolRunner.
Passive-first, optional Active scan; pulls alerts via ZAP API; merges duplicates;
produces standardized findings.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    RiskLevel,
    ToolCategory,
)
from app.utils.logger import logger


class ZapScannerWrapper(BaseToolWrapper):
    """OWASP ZAP wrapper (daemon mode)."""

    name = "zap_scanner"
    category = ToolCategory.DISCOVERY
    description = "OWASP ZAP wrapper"
    version = "2.14"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None, validate_binary: bool = False):
        # ZAP runs as service; skip binary validation by default
        self.session = requests.Session()
        self.validate_binary = validate_binary
        super().__init__(config=config)

    def _validate_dependencies(self):
        if not getattr(self, "validate_binary", False):
            return
        return super()._validate_dependencies()

    # BaseToolWrapper requirement; ZAP is API-driven so parse_output not used
    def parse_output(self, raw_output: str):  # pragma: no cover - unused
        return []

    # ---- Public API ----
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = time.time()
        errors: List[str] = []
        findings: List[Dict[str, Any]] = []
        success = False

        try:
            host = opts.get("zap_host") or self.config.get("zap_host", "http://127.0.0.1:8080")
            api_key = opts.get("api_key") or self.config.get("api_key")
            context_name = opts.get("context") or "scanner_context"
            do_active = bool(opts.get("active_scan"))
            seed_endpoints = opts.get("seed_endpoints") or []
            rate_limit_ms = int(opts.get("rate_limit_ms", 0))
            scope = opts.get("scope") or target

            base_params = {"apikey": api_key} if api_key else {}

            # Scope enforcement: register context and include target
            context_id = self._ensure_context(host, context_name, target, base_params)

            # Seed endpoints into ZAP (e.g., from DirScanner)
            if seed_endpoints:
                self._import_urls(host, seed_endpoints, base_params)

            # Start spider
            self._spider(host, target, context_name, base_params)
            self._wait_for_spider(host, base_params)

            # Wait for passive scan to finish
            self._wait_for_passive(host, base_params)

            # Optional active scan
            if do_active:
                self._active_scan(host, target, context_id, base_params, rate_limit_ms)
                self._wait_for_active(host, base_params)

            # Fetch alerts and convert to findings
            alerts = self._fetch_alerts(host, scope, base_params)
            findings = self._alerts_to_findings(alerts, do_active)
            success = True
        except Exception as exc:  # noqa: BLE001
            logger.error("ZapScannerWrapper failed", exc_info=True)
            errors.append(str(exc))
            success = False

        duration = time.time() - start_ts
        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=datetime.now(timezone.utc),
            duration=duration,
            success=success,
            findings=findings,
            raw_output="",
            errors=errors,
            metadata={"active_scan": do_active},
            exit_code=0 if success else 1,
            stdout="",
            stderr="",
        )

    # ---- ZAP API helpers ----
    def _ensure_context(self, host: str, context_name: str, target: str, params: Dict[str, Any]) -> str:
        # Create context if missing
        existing = self._get_json(f"{host}/JSON/context/view/contextList/", params)
        if context_name not in existing.get("contextList", []):
            self._get_json(f"{host}/JSON/context/action/newContext/", {**params, "contextName": context_name})

        # Include target in context regex (simple prefix)
        include_regex = f"^{target}.*"
        self._get_json(
            f"{host}/JSON/context/action/includeInContext/",
            {**params, "contextName": context_name, "regex": include_regex},
        )
        ctx = self._get_json(f"{host}/JSON/context/view/context/", {**params, "contextName": context_name})
        return str(ctx.get("context", [{}])[0].get("id", "0"))

    def _import_urls(self, host: str, urls: List[str], params: Dict[str, Any]):
        for url in urls:
            self._get_json(f"{host}/JSON/core/action/accessUrl/", {**params, "url": url})

    def _spider(self, host: str, target: str, context_name: str, params: Dict[str, Any]):
        self._get_json(
            f"{host}/JSON/spider/action/scan/",
            {**params, "contextName": context_name, "url": target, "maxChildren": 0},
        )

    def _wait_for_spider(self, host: str, params: Dict[str, Any], timeout: int = 300):
        start = time.time()
        while True:
            status = self._get_json(f"{host}/JSON/spider/view/status/", params).get("status")
            if status == "100":
                return
            if time.time() - start > timeout:
                raise TimeoutError("ZAP spider timeout")
            time.sleep(2)

    def _wait_for_passive(self, host: str, params: Dict[str, Any], timeout: int = 300):
        start = time.time()
        while True:
            scan_status = self._get_json(f"{host}/JSON/pscan/view/recordsToScan/", params)
            if scan_status.get("recordsToScan") in ("0", 0):
                return
            if time.time() - start > timeout:
                raise TimeoutError("ZAP passive scan timeout")
            time.sleep(2)

    def _active_scan(self, host: str, target: str, context_id: str, params: Dict[str, Any], rate_limit_ms: int):
        payload = {**params, "url": target, "contextId": context_id}
        if rate_limit_ms:
            payload["delayInMs"] = rate_limit_ms
        self._get_json(f"{host}/JSON/ascan/action/scan/", payload)

    def _wait_for_active(self, host: str, params: Dict[str, Any], timeout: int = 600):
        start = time.time()
        while True:
            status = self._get_json(f"{host}/JSON/ascan/view/status/", params).get("status")
            if status == "100":
                return
            if time.time() - start > timeout:
                raise TimeoutError("ZAP active scan timeout")
            time.sleep(3)

    def _fetch_alerts(self, host: str, scope: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = self._get_json(f"{host}/JSON/alert/view/alerts/", {**params, "baseurl": scope, "start": 0, "count": 9999})
        return alerts.get("alerts", []) if isinstance(alerts, dict) else []

    def _get_json(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {}

    # ---- Alert parsing ----
    def _alerts_to_findings(self, alerts: List[Dict[str, Any]], active: bool) -> List[Dict[str, Any]]:
        merged: Dict[tuple, Dict[str, Any]] = {}
        for alert in alerts:
            risk = self._map_risk(alert.get("risk", alert.get("riskcode")))
            if risk is None:
                continue
            title = alert.get("alert", "OWASP ZAP Alert")
            url = alert.get("url", "")
            param = alert.get("param") or ""
            evidence = alert.get("evidence") or ""
            desc = alert.get("description") or alert.get("solution") or ""
            cwe = alert.get("cweid") or None
            wasc = alert.get("wascid") or None
            confidence = self._confidence(alert.get("confidence"), bool(evidence), active)
            verification_status = "verified" if active else "unverified"

            key = (title, url, param, risk.value)
            if key not in merged:
                merged[key] = {
                    "title": title,
                    "description": desc,
                    "risk_level": risk.value,
                    "affected_url": url,
                    "recommendation": alert.get("solution", "Review and remediate as per OWASP ZAP guidance."),
                    "evidence": {
                        "param": param,
                        "evidence": evidence,
                        "cwe": cwe,
                        "wasc": wasc,
                        "references": alert.get("reference") or alert.get("tags"),
                    },
                    "cwe_id": str(cwe) if cwe else None,
                    "cvss_score": self._cvss_from_risk(risk),
                    "confidence_score": confidence,
                    "detection_method": "owasp_zap",
                    "verification_status": verification_status,
                }
                continue

            # merge duplicates: accumulate evidence
            ev = merged[key].setdefault("evidence", {})
            refs = ev.setdefault("references", [])
            new_ref = alert.get("reference") or alert.get("tags")
            if new_ref and new_ref not in refs:
                if isinstance(new_ref, list):
                    refs.extend([r for r in new_ref if r not in refs])
                else:
                    refs.append(new_ref)
            if evidence:
                existing_ev = ev.get("evidence", "") or ""
                if evidence not in existing_ev:
                    ev["evidence"] = f"{existing_ev}\n{evidence}" if existing_ev else evidence
        return list(merged.values())

    def _map_risk(self, risk: Any) -> Optional[RiskLevel]:
        mapping = {
            "0": None,
            "1": RiskLevel.MEDIUM,
            "2": RiskLevel.HIGH,
            "3": RiskLevel.CRITICAL,
            0: None,
            1: RiskLevel.MEDIUM,
            2: RiskLevel.HIGH,
            3: RiskLevel.CRITICAL,
            "Informational": None,
            "Low": RiskLevel.MEDIUM,
            "Medium": RiskLevel.HIGH,
            "High": RiskLevel.CRITICAL,
        }
        if risk is None:
            return None
        return mapping.get(risk, None)

    def _confidence(self, confidence: Any, has_evidence: bool, active: bool) -> float:
        base_map = {
            "0": 0.5,
            "1": 0.6,
            "2": 0.75,
            "3": 0.85,
            "4": 0.9,
            0: 0.5,
            1: 0.6,
            2: 0.75,
            3: 0.85,
            4: 0.9,
        }
        base = base_map.get(confidence, 0.7)
        if has_evidence:
            base += 0.05
        if active:
            base += 0.05
        return min(base, 0.98)

    def _cvss_from_risk(self, risk: RiskLevel) -> float:
        if risk == RiskLevel.CRITICAL:
            return 9.0
        if risk == RiskLevel.HIGH:
            return 7.5
        if risk == RiskLevel.MEDIUM:
            return 5.0
        return 0.0
