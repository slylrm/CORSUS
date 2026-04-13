"""
DirScanner Wrapper - Gobuster-based directory/endpoint discovery.
Production-ready, ScannerEngine/ToolRunner compatible.
"""

import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    RiskLevel,
    ToolCategory,
)
from app.utils.logger import logger


class DirScannerWrapper(BaseToolWrapper):
    """Directory and endpoint discovery using gobuster (preferred)."""

    name = "gobuster"
    category = ToolCategory.DISCOVERY
    description = "Directory and endpoint discovery"
    version = "3.x"
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
        errors: List[str] = []

        command = self._build_command(target, opts)

        try:
            result = self._execute_command(command, timeout=timeout)
            raw_output = result.stdout or ""
            parsed_findings = self.parse_output(raw_output, target)
            success = result.returncode == 0 or bool(parsed_findings)
        except Exception as exc:  # noqa: BLE001
            raw_output = ""
            parsed_findings = []
            success = False
            errors.append(str(exc))
            self.logger.error("DirScanner execution failed", exc_info=True)

        duration = time.time() - start_ts

        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=datetime.now(timezone.utc),
            duration=duration,
            success=success,
            findings=parsed_findings,
            raw_output=raw_output,
            errors=errors,
            metadata={"command": " ".join(command)},
            exit_code=0 if success else 1,
            stdout=raw_output,
            stderr="",
        )

    def _build_command(self, target: str, opts: Dict[str, Any]) -> List[str]:
        wordlist = opts.get("wordlist") or self.config.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"
        threads = str(opts.get("threads", 10))
        follow_redirect = opts.get("follow_redirects", False)
        insecure_tls = opts.get("insecure", False)

        cmd = [self.name, "dir", "-u", target, "-w", wordlist, "-t", threads, "-q"]
        if follow_redirect:
            cmd.append("-r")
        if insecure_tls:
            cmd.append("-k")
        if opts.get("extensions"):
            cmd.extend(["-x", opts["extensions"]])
        if opts.get("status_codes"):
            cmd.extend(["-s", opts["status_codes"]])
        return cmd

    def parse_output(self, raw_output: str, target: Optional[str] = None) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not raw_output:
            return findings

        for line in raw_output.splitlines():
            parsed = self._parse_line(line.strip(), target)
            if parsed:
                findings.append(parsed)

        return self._merge_findings(findings)

    def _parse_line(self, line: str, target: Optional[str]) -> Optional[Dict[str, Any]]:
        if not line or line.startswith("#"):
            return None

        # Gobuster common format: /admin (Status: 301) [Size: 0] [--> https://example.com/admin/]
        m = re.match(r"^(?P<path>[^\s]+)\s+\(Status:\s*(?P<status>\d{3})\).*?(Size:\s*(?P<size>\d+))?", line)
        if not m:
            return None

        status = int(m.group("status"))
        path = m.group("path")
        if status >= 404:
            return None

        severity = self._severity_from_status(status)
        confidence = self._confidence_from_status(status, m.group("size"))
        affected_url = f"{target.rstrip('/')}{path}" if target else path

        finding = {
            "title": self._title_from_status(status),
            "description": f"Endpoint discovered: {path} (status {status})",
            "risk_level": severity.value,
            "affected_url": affected_url,
            "recommendation": self._recommendation_from_status(status),
            "evidence": {
                "raw": line,
                "status_code": status,
                "path": path,
                "size": int(m.group("size")) if m.group("size") else None,
            },
            "confidence_score": confidence,
            "detection_method": "dir_scanner",
            "verification_status": "unverified",
        }
        return finding

    def _severity_from_status(self, status: int) -> RiskLevel:
        if status in (401, 403):
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _title_from_status(self, status: int) -> str:
        if status in (401, 403):
            return "Restricted Resource Discovered"
        return "Exposed Directory Detected"

    def _recommendation_from_status(self, status: int) -> str:
        if status in (401, 403):
            return "Review access controls and ensure proper authorization for this resource."
        return "Review necessity of the exposed path and restrict or remove if not intended to be public."

    def _confidence_from_status(self, status: int, size: Optional[str]) -> float:
        base = 0.9 if status in (200, 301, 302) else 0.75 if status in (401, 403) else 0.0
        if size:
            try:
                sz = int(size)
                if sz == 0:
                    base -= 0.05
                elif sz > 5000:
                    base += 0.05
            except Exception:
                pass
        return max(0.5, min(base, 0.95)) if base > 0 else 0.0

    def _merge_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for item in findings:
            key = (item.get("affected_url"), item.get("risk_level"))
            if key not in merged:
                merged[key] = item
                merged[key].setdefault("evidence", {}).setdefault("sources", [self.name])
                continue

            existing = merged[key]
            evidence = existing.setdefault("evidence", {})
            sources = evidence.setdefault("sources", [])
            if self.name not in sources:
                sources.append(self.name)

            # merge raw evidence lines if different
            raw = evidence.get("raw")
            new_raw = item.get("evidence", {}).get("raw")
            if new_raw and new_raw not in (raw or ""):
                evidence["raw"] = f"{raw}\n{new_raw}" if raw else new_raw

        return list(merged.values())
