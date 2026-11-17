"""
Semgrep Wrapper - Static Application Security Testing (SAST)
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

class SemgrepWrapper(BaseToolWrapper):
    """
    Semgrep SAST tool wrapper
    """
    
    name = "semgrep"
    category = ToolCategory.CUSTOM  # Or SAST if we added it to ToolCategory
    description = "Ultra-fast static analysis tool for code-level vulnerabilities"
    version = "1.66"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.semgrep_path = config.get("path", getattr(settings, "SEMGREP_PATH", "semgrep")) if config else getattr(settings, "SEMGREP_PATH", "semgrep")
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Semgrep çalıştır.
        Not: Target SAST için genelde bir klasör yolu olmalıdır, web URL yerine.
        """
        start_time = datetime.now()
        options = options or {}
        
        json_output = settings.SEMGREP_OUTPUT_DIR / f"semgrep_{datetime.now().timestamp()}.json"
        json_output.parent.mkdir(parents=True, exist_ok=True)
        
        command = [
            self.semgrep_path,
            "scan",
            "--config", "auto",
            "--json",
            "--output", str(json_output),
            target  # In context of Semgrep, target should be a local path
        ]
        
        findings = []
        errors = []
        raw_output = ""
        success = False
        
        try:
            result = self._execute_command(command, timeout=300)
            raw_output = result.stdout + result.stderr
            
            if json_output.exists():
                findings = self.parse_json_output(json_output)

            if result.returncode != 0:
                error_detail = result.stderr.strip() or result.stdout.strip() or f"Exit code {result.returncode}"
                errors.append(error_detail[:500])
            
            success = result.returncode == 0 or len(findings) > 0
            
        except Exception as e:
            self.logger.error(f"Semgrep execution failed: {e}")
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
    
    def parse_json_output(self, json_file: Path) -> List[Finding]:
        """Parse Semgrep JSON output"""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            results = data.get("results", [])
            for res in results:
                extra = res.get("extra", {})
                
                raw_severity = extra.get("severity", "INFO")
                risk_mapping = {
                    "INFO": RiskLevel.INFO,
                    "WARNING": RiskLevel.MEDIUM,
                    "ERROR": RiskLevel.HIGH,
                }
                risk_level = risk_mapping.get(raw_severity, RiskLevel.INFO)
                
                finding = Finding(
                    title=res.get("check_id", "Semgrep Finding"),
                    description=extra.get("message", ""),
                    risk_level=risk_level,
                    affected_url=f"file://{res.get('path')}#L{res.get('start', {}).get('line', '')}",
                    evidence={
                        "path": res.get("path"),
                        "start_line": res.get("start", {}).get("line"),
                        "end_line": res.get("end", {}).get("line"),
                        "match": extra.get("lines", "").strip()
                    },
                    recommendation="Review the code snippet to ensure secure implementation based on semgrep rules.",
                    verified=True
                )
                
                findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse semgrep JSON: {e}")
            
        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        return []
