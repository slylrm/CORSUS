"""
ZapScannerWrapper - ASYNC VERSION
OWASP ZAP integration with non-blocking wait loops
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    RiskLevel,
    ToolCategory,
)
from app.utils.logger import logger


class ZapScannerWrapperAsync(BaseToolWrapper):
    """OWASP ZAP wrapper (async, non-blocking)."""

    name = "zap_scanner"
    category = ToolCategory.DISCOVERY
    description = "OWASP ZAP async wrapper"
    version = "2.14"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Skip binary validation for ZAP (API-driven)
        self.validate_binary = False
        super().__init__(config=config)
    
    def _validate_dependencies(self):
        # ZAP runs as service; skip binary validation
        pass

    def parse_output(self, raw_output: str):
        # Not used for API-driven tools
        return []

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Sync wrapper for async run - required by BaseToolWrapper
        This will be called from ToolRunner in executor
        """
        # Run async code in event loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already in async context - create new task
            future = asyncio.ensure_future(self.run_async(target, options))
            # Wait for completion (blocking in executor)
            return asyncio.get_event_loop().run_until_complete(future)
        else:
            return loop.run_until_complete(self.run_async(target, options))

    async def run_async(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        ✅ ASYNC VERSION: No blocking time.sleep(), all awaitable
        """
        opts = options or {}
        start_ts = asyncio.get_event_loop().time()
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

            # Use httpx async client
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Context setup
                context_id = await self._ensure_context(client, host, context_name, target, base_params)
                
                # Seed URLs
                if seed_endpoints:
                    await self._import_urls(client, host, seed_endpoints, base_params)
                
                # Spider
                await self._spider(client, host, target, context_name, base_params)
                await self._wait_for_spider(client, host, base_params)
                
                # Passive scan
                await self._wait_for_passive(client, host, base_params)
                
                # Optional active scan
                if do_active:
                    await self._active_scan(client, host, target, context_id, base_params, rate_limit_ms)
                    await self._wait_for_active(client, host, base_params)
                
                # Fetch alerts
                alerts = await self._fetch_alerts(client, host, scope, base_params)
                findings = self._alerts_to_findings(alerts, do_active)
                success = True
                
        except Exception as exc:
            logger.error(f"[ZAP ASYNC] Failed: {exc}", exc_info=True)
            errors.append(str(exc))
            success = False

        duration = asyncio.get_event_loop().time() - start_ts
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

    # ---- ASYNC ZAP API helpers ----
    async def _ensure_context(self, client: httpx.AsyncClient, host: str, context_name: str, target: str, params: Dict[str, Any]) -> str:
        existing = await self._get_json(client, f"{host}/JSON/context/view/contextList/", params)
        if context_name not in existing.get("contextList", []):
            await self._get_json(client, f"{host}/JSON/context/action/newContext/", {**params, "contextName": context_name})
        
        include_regex = f"^{target}.*"
        await self._get_json(
            client,
            f"{host}/JSON/context/action/includeInContext/",
            {**params, "contextName": context_name, "regex": include_regex},
        )
        ctx = await self._get_json(client, f"{host}/JSON/context/view/context/", {**params, "contextName": context_name})
        return str(ctx.get("context", [{}])[0].get("id", "0"))

    async def _import_urls(self, client: httpx.AsyncClient, host: str, urls: List[str], params: Dict[str, Any]):
        for url in urls:
            await self._get_json(client, f"{host}/JSON/core/action/accessUrl/", {**params, "url": url})

    async def _spider(self, client: httpx.AsyncClient, host: str, target: str, context_name: str, params: Dict[str, Any]):
        await self._get_json(
            client,
            f"{host}/JSON/spider/action/scan/",
            {**params, "contextName": context_name, "url": target, "maxChildren": 0},
        )

    async def _wait_for_spider(self, client: httpx.AsyncClient, host: str, params: Dict[str, Any], timeout: int = 300):
        """✅ NON-BLOCKING: asyncio.sleep instead of time.sleep"""
        start = asyncio.get_event_loop().time()
        while True:
            status = (await self._get_json(client, f"{host}/JSON/spider/view/status/", params)).get("status")
            if status == "100":
                logger.info("[ZAP] Spider completed")
                return
            if asyncio.get_event_loop().time() - start > timeout:
                raise TimeoutError("ZAP spider timeout")
            await asyncio.sleep(2)  # ✅ Non-blocking

    async def _wait_for_passive(self, client: httpx.AsyncClient, host: str, params: Dict[str, Any], timeout: int = 300):
        """✅ NON-BLOCKING: asyncio.sleep instead of time.sleep"""
        start = asyncio.get_event_loop().time()
        while True:
            scan_status = await self._get_json(client, f"{host}/JSON/pscan/view/recordsToScan/", params)
            if scan_status.get("recordsToScan") in ("0", 0):
                logger.info("[ZAP] Passive scan completed")
                return
            if asyncio.get_event_loop().time() - start > timeout:
                raise TimeoutError("ZAP passive scan timeout")
            await asyncio.sleep(2)  # ✅ Non-blocking

    async def _active_scan(self, client: httpx.AsyncClient, host: str, target: str, context_id: str, params: Dict[str, Any], rate_limit_ms: int):
        payload = {**params, "url": target, "contextId": context_id}
        if rate_limit_ms:
            payload["delayInMs"] = rate_limit_ms
        await self._get_json(client, f"{host}/JSON/ascan/action/scan/", payload)

    async def _wait_for_active(self, client: httpx.AsyncClient, host: str, params: Dict[str, Any], timeout: int = 600):
        """✅ NON-BLOCKING: asyncio.sleep instead of time.sleep"""
        start = asyncio.get_event_loop().time()
        while True:
            status = (await self._get_json(client, f"{host}/JSON/ascan/view/status/", params)).get("status")
            if status == "100":
                logger.info("[ZAP] Active scan completed")
                return
            if asyncio.get_event_loop().time() - start > timeout:
                raise TimeoutError("ZAP active scan timeout")
            await asyncio.sleep(3)  # ✅ Non-blocking

    async def _fetch_alerts(self, client: httpx.AsyncClient, host: str, scope: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = await self._get_json(client, f"{host}/JSON/alert/view/alerts/", {**params, "baseurl": scope, "start": 0, "count": 9999})
        return alerts.get("alerts", []) if isinstance(alerts, dict) else []

    async def _get_json(self, client: httpx.AsyncClient, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """✅ ASYNC HTTP: httpx.AsyncClient"""
        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"[ZAP API] Error fetching {url}: {e}")
            return {}

    # ---- Alert parsing (sync, no blocking) ----
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

            # Merge duplicates
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
