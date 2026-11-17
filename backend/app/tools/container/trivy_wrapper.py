"""
Trivy Wrapper - Container and Infrastructure Scanner
"""

from typing import Dict, List, Any, Optional
import json
from datetime import datetime
from pathlib import Path

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.config import settings

class TrivyWrapper(BaseToolWrapper):
    """
    Trivy vulnerability scanner wrapper
    """
    
    name = "trivy"
    category = ToolCategory.MISCONFIGURATION  # or Container
    description = "Comprehensive container, Kubernetes, and infrastructure vulnerability scanner"
    version = "0.49"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.trivy_path = config.get("path", getattr(settings, "TRIVY_PATH", "trivy")) if config else getattr(settings, "TRIVY_PATH", "trivy")
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Trivy çalıştır
        target: can be fs path, repo url, or image name
        options: {
            "scan_type": "fs" | "image" | "repo" | "k8s" 
        }
        """
        start_time = datetime.now()
        options = options or {}
        scan_type = options.get("scan_type", "fs")  # Default to file system analysis
        try:
            command_timeout = max(30, int(options.get("timeout", 300)))
        except (TypeError, ValueError):
            command_timeout = 300
        scanners = str(options.get("scanners", "vuln")).strip() or "vuln"
        skip_version_check = bool(options.get("skip_version_check", True))
        quiet = bool(options.get("quiet", True))
        
        json_output = settings.TRIVY_OUTPUT_DIR / f"trivy_{datetime.now().timestamp()}.json"
        json_output.parent.mkdir(parents=True, exist_ok=True)
        
        command = [
            self.trivy_path,
            scan_type,
            "--format", "json",
            "--output", str(json_output),
            "--timeout", f"{command_timeout}s",
            "--scanners", scanners,
            target
        ]

        if skip_version_check:
            command.append("--skip-version-check")

        if quiet:
            command.append("--quiet")
        
        if options.get("severity"):
             command.extend(["--severity", options.get("severity")])
             
        findings = []
        errors = []
        raw_output = ""
        success = False
        
        try:
            # Keep subprocess timeout slightly above Trivy's own timeout to allow clean exit.
            result = self._execute_command(command, timeout=command_timeout + 15)
            raw_output = result.stdout + result.stderr
            
            if json_output.exists():
                findings = self.parse_json_output(json_output)

            if result.returncode == -1 and "timed out" in (result.stderr or "").lower():
                errors.append(f"TIMEOUT after {command_timeout}s")
            elif result.returncode != 0:
                error_detail = self._extract_error_detail(result.returncode, result.stdout, result.stderr)
                errors.append(error_detail[:500])
            
            success = result.returncode == 0 or len(findings) > 0
            
        except Exception as e:
            self.logger.error(f"Trivy execution failed: {e}")
            errors.append(str(e))
            success = False
            
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=start_time,
            duration=duration,
            success=success,
            findings=[f.to_dict() for f in findings],
            raw_output=raw_output,
            errors=errors,
            metadata={"command": " ".join(command)}
        )

    def _extract_error_detail(self, returncode: int, stdout: str, stderr: str) -> str:
        combined = (stderr or "").strip() or (stdout or "").strip()
        if not combined:
            return f"Exit code {returncode}"

        lower = combined.lower()
        if any(token in lower for token in ("fatal", "panic", "failed", "unable", "cannot", "error:")):
            return combined

        # Trivy emits INFO/WARN notices on stderr; avoid reporting these as hard errors.
        return f"Trivy exited with code {returncode} without parsable findings"
    
    def parse_json_output(self, json_file: Path) -> List[Finding]:
        """Parse Trivy JSON output"""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            results = data.get("Results", [])
            for res in results:
                target_name = res.get("Target", "Unknown")
                vulnerabilities = res.get("Vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    raw_severity = vuln.get("Severity", "UNKNOWN")
                    risk_mapping = {
                        "UNKNOWN": RiskLevel.INFO,
                        "LOW": RiskLevel.LOW,
                        "MEDIUM": RiskLevel.MEDIUM,
                        "HIGH": RiskLevel.HIGH,
                        "CRITICAL": RiskLevel.CRITICAL
                    }
                    risk_level = risk_mapping.get(raw_severity, RiskLevel.INFO)
                    
                    finding = Finding(
                        title=f"{vuln.get('VulnerabilityID')} - {vuln.get('PkgName')}",
                        description=vuln.get("Description", vuln.get("Title", "-")),
                        risk_level=risk_level,
                        affected_url=target_name,
                        evidence={
                            "Package": vuln.get("PkgName"),
                            "InstalledVersion": vuln.get("InstalledVersion"),
                            "FixedVersion": vuln.get("FixedVersion"),
                            "Layer": vuln.get("Layer")
                        },
                        recommendation=f"Update {vuln.get('PkgName')} to version {vuln.get('FixedVersion', 'latest')}" if vuln.get("FixedVersion") else "Monitor for upstream patches.",
                        cwe_id=vuln.get("CweIDs", [None])[0] if vuln.get("CweIDs") else None,
                        verified=True
                    )
                    
                    findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse trivy JSON: {e}")
            
        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        return []
