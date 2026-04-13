"""
Nikto Wrapper - Web Server Misconfiguration Scanner
Production-ready tool wrapper compatible with ScannerEngine/ToolRunner.
"""

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory,
)
from app.utils.logger import logger


class NiktoWrapper(BaseToolWrapper):
    """Nikto tool wrapper (technology/misconfiguration discovery)."""

    name = "nikto"
    category = ToolCategory.DISCOVERY
    description = "Nikto web server scanner"
    version = "2.5.x"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None, validate_binary: bool = True):
        self.validate_binary = validate_binary
        super().__init__(config=config)

    def _validate_dependencies(self):
        if not getattr(self, "validate_binary", True):
            return
        return super()._validate_dependencies()

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = time.time()
        timeout = int(opts.get("timeout", 300))

        command = self._build_command(target, opts)
        errors: List[str] = []

        try:
            result = self._execute_command(command, timeout=timeout)
            raw_output = result.stdout or ""
            findings = [f.to_dict() if isinstance(f, Finding) else f for f in self.parse_output(raw_output, target)]
            success = result.returncode == 0 or bool(findings)
        except Exception as exc:  # noqa: BLE001
            raw_output = ""
            findings = []
            success = False
            errors.append(str(exc))
            self.logger.error("Nikto execution failed", exc_info=True)

        duration = time.time() - start_ts

        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=datetime.now(timezone.utc),
            duration=duration,
            success=success,
            findings=findings,
            raw_output=raw_output,
            errors=errors,
            metadata={"command": " ".join(command)},
            exit_code=0 if success else 1,
            stdout=raw_output,
            stderr="",
        )

    def _build_command(self, target: str, opts: Dict[str, Any]) -> List[str]:
        command = [self.name, "-h", target, "-Format", "json", "-output", "-"]

        if opts.get("port"):
            command.extend(["-port", str(opts["port"])])
        if opts.get("ssl"):
            command.append("-ssl")
        if opts.get("plugins"):
            command.extend(["-Plugins", str(opts["plugins"])])
        if opts.get("timeout"):
            command.extend(["-timeout", str(int(opts["timeout"]))])

        return command

    def parse_output(self, raw_output: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not raw_output:
            return findings

        json_data = self._safe_json_loads(raw_output)
        if json_data is not None:
            findings.extend(self._parse_json_records(json_data, target))
        else:
            findings.extend(self._parse_text_output(raw_output, target))

        return self._merge_findings(findings)

    def _safe_json_loads(self, raw_output: str) -> Optional[Any]:
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            try:
                start = raw_output.find("{")
                end = raw_output.rfind("}")
                if start != -1 and end != -1:
                    return json.loads(raw_output[start : end + 1])
            except Exception:
                return None
        except Exception:
            return None
        return None

    def _parse_json_records(self, data: Any, target: Optional[str]) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            if "vulnerabilities" in data or "findings" in data:
                records = [data]
            elif "hosts" in data and isinstance(data["hosts"], list):
                records = data["hosts"]
            else:
                records = [data]
        elif isinstance(data, list):
            records = data

        findings: List[Dict[str, Any]] = []
        for record in records:
            vulns = record.get("vulnerabilities") or record.get("findings") or record.get("issues") or []
            if isinstance(vulns, dict):
                vulns = list(vulns.values())

            for vuln in vulns:
                message = vuln.get("msg") or vuln.get("description") or vuln.get("issue") or "Unspecified issue"
                endpoint = vuln.get("url") or vuln.get("uri") or record.get("url") or target or ""
                severity = self._map_severity(vuln.get("severity"))
                issue_type = self._classify_issue(message, vuln)
                references = self._extract_references(vuln)
                has_reference = bool(references)
                confidence = self._confidence_score(severity, has_reference, from_text=False)

                finding = {
                    "title": self._build_title(issue_type),
                    "description": self._build_description(message, endpoint),
                    "risk_level": severity.value,
                    "affected_url": endpoint or (target or ""),
                    "recommendation": self._recommendation(issue_type),
                    "evidence": {
                        "raw": message,
                        "endpoint": endpoint,
                        "issue_type": issue_type,
                        "references": references,
                        "potential_false_positive": self._is_potential_fp(message, severity),
                    },
                    "confidence_score": confidence,
                    "detection_method": "nikto",
                    "verification_status": "needs_manual_verification",
                }
                findings.append(finding)
        return findings

    def _parse_text_output(self, raw_output: str, target: Optional[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("--"):
                continue
            message = line.lstrip("+ ")
            severity = self._map_severity_from_message(message)
            issue_type = self._classify_issue(message, {})
            endpoint = target or ""
            confidence = self._confidence_score(severity, has_reference=False, from_text=True)

            finding = {
                "title": self._build_title(issue_type),
                "description": self._build_description(message, endpoint),
                "risk_level": severity.value,
                "affected_url": endpoint,
                "recommendation": self._recommendation(issue_type),
                "evidence": {
                    "raw": message,
                    "endpoint": endpoint,
                    "issue_type": issue_type,
                    "potential_false_positive": self._is_potential_fp(message, severity),
                },
                "confidence_score": confidence,
                "detection_method": "nikto",
                "verification_status": "needs_manual_verification",
            }
            findings.append(finding)
        return findings

    def _merge_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for item in findings:
            key = (item.get("title"), item.get("risk_level"), item.get("description"))
            endpoint = item.get("evidence", {}).get("endpoint")
            if key not in merged:
                if endpoint:
                    item.setdefault("evidence", {}).setdefault("endpoints", [endpoint])
                merged[key] = item
                continue

            existing = merged[key]
            endpoints = existing.setdefault("evidence", {}).setdefault("endpoints", [])
            if endpoint and endpoint not in endpoints:
                endpoints.append(endpoint)
            existing["evidence"]["count"] = len(endpoints) if endpoints else 1
        return list(merged.values())

    def _map_severity(self, severity: Any) -> RiskLevel:
        mapping = {
            "0": RiskLevel.LOW,
            "1": RiskLevel.LOW,
            "2": RiskLevel.MEDIUM,
            "3": RiskLevel.HIGH,
            "low": RiskLevel.LOW,
            "medium": RiskLevel.MEDIUM,
            "high": RiskLevel.HIGH,
        }
        if severity is None:
            return RiskLevel.MEDIUM
        if isinstance(severity, int):
            return mapping.get(str(severity), RiskLevel.MEDIUM)
        if isinstance(severity, str):
            return mapping.get(severity.lower(), RiskLevel.MEDIUM)
        return RiskLevel.MEDIUM

    def _map_severity_from_message(self, message: str) -> RiskLevel:
        lower = message.lower()
        if any(tok in lower for tok in ["critical", "remote code", "rce"]):
            return RiskLevel.HIGH
        if any(tok in lower for tok in ["outdated", "obsolete", "old version", "sql injection", "xss"]):
            return RiskLevel.HIGH
        if any(tok in lower for tok in ["directory listing", "default", "backup", "debug"]):
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _classify_issue(self, message: str, vuln: Dict[str, Any]) -> str:
        text = message.lower()
        if any(k in text for k in ["outdated", "obsolete", "old version", "out of date"]):
            return "outdated_software"
        if any(k in text for k in ["header", "cookie", "cors", "x-", "strict-transport", "x-frame"]):
            return "dangerous_headers"
        if any(k in text for k in ["default", "backup", "example", "test", "phpinfo", "admin"]):
            return "default_files"
        if any(k in text for k in ["config", "misconfiguration", "dir listing", "directory listing"]):
            return "misconfiguration"
        return "misconfiguration"

    def _build_title(self, issue_type: str) -> str:
        titles = {
            "misconfiguration": "Web Server Misconfiguration",
            "outdated_software": "Outdated Web Server Component",
            "dangerous_headers": "Insecure HTTP Header Configuration",
            "default_files": "Default or Backup File Exposed",
        }
        return titles.get(issue_type, "Web Server Issue Detected")

    def _build_description(self, message: str, endpoint: str) -> str:
        endpoint_part = f" at {endpoint}" if endpoint else ""
        return f"Nikto reported: {message}{endpoint_part}"

    def _recommendation(self, issue_type: str) -> str:
        recommendations = {
            "misconfiguration": "Harden web server configuration and disable unnecessary options.",
            "outdated_software": "Update the server/component to the latest stable version.",
            "dangerous_headers": "Set secure HTTP headers (HSTS, X-Frame-Options, CSP, etc.).",
            "default_files": "Remove default/admin/backup files and restrict directory listing.",
        }
        return recommendations.get(issue_type, "Review and remediate the reported issue.")

    def _extract_references(self, vuln: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        for key in ["osvdb", "cve", "id", "references"]:
            val = vuln.get(key)
            if not val:
                continue
            if isinstance(val, list):
                refs.extend([str(x) for x in val])
            else:
                refs.append(str(val))
        return list({r for r in refs})

    def _confidence_score(self, severity: RiskLevel, has_reference: bool, from_text: bool) -> float:
        base = 0.6 if from_text else 0.75
        if severity == RiskLevel.HIGH:
            base += 0.05
        if has_reference:
            base += 0.05
        return min(base, 0.95)

    def _is_potential_fp(self, message: str, severity: RiskLevel) -> bool:
        text = message.lower()
        if "possible" in text or "might" in text or "may" in text:
            return True
        return severity == RiskLevel.LOW
