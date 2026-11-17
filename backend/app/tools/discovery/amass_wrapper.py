"""
Amass Wrapper - Asset Discovery
"""

from typing import Dict, List, Any, Optional, Tuple
import json
import re
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

class AmassWrapper(BaseToolWrapper):
    """
    OWASP Amass tool wrapper for asset discovery
    """
    
    name = "amass"
    category = ToolCategory.DISCOVERY
    description = "In-depth asset discovery and attack surface mapping (OWASP)"
    version = "4.2"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.amass_path = config.get("path", getattr(settings, "AMASS_PATH", "amass")) if config else getattr(settings, "AMASS_PATH", "amass")
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Amass çalıştır
        """
        start_time = datetime.now()
        options = options or {}
        
        # JSON output için (canonical path from settings)
        json_output = settings.AMASS_OUTPUT_DIR / f"amass_{datetime.now().timestamp()}.json"
        json_output.parent.mkdir(parents=True, exist_ok=True)
        output_prefix = json_output.with_suffix("")
        
        findings = []
        errors = []
        raw_output = ""
        success = False
        command: List[str] = []
        
        try:
            result, command = self._run_amass(target, json_output, options)
            raw_output = (result.stdout or "") + (result.stderr or "")

            resolved_json = self._resolve_amass_json_output(output_prefix, json_output)
            if resolved_json:
                findings = self.parse_json_lines(resolved_json)
            else:
                findings = self.parse_text_output(raw_output, target)
                if findings:
                    self.logger.info("Amass JSON output not found, parsed {} findings from stdout", len(findings))
                else:
                    self.logger.info("Amass JSON output not found and stdout fallback was empty")

            if result.returncode != 0 and not findings:
                error_detail = (result.stderr or "").strip() or (result.stdout or "").strip() or f"Exit code {result.returncode}"
                errors.append(error_detail[:1000])

            success = result.returncode == 0 or len(findings) > 0
            
        except Exception as e:
            self.logger.error(f"Amass execution failed: {e}")
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
            metadata={"command": " ".join(command) if command else ""}
        )

    def _resolve_amass_json_output(self, output_prefix: Path, requested_json_path: Path) -> Optional[Path]:
        direct_json = output_prefix.with_suffix(".json")
        if direct_json.exists():
            return direct_json
        if requested_json_path.exists():
            return requested_json_path

        for candidate in sorted(output_prefix.parent.glob(f"{output_prefix.name}*.json")):
            if candidate.exists():
                return candidate
        return None

    def _run_amass(self, target: str, json_output: Path, options: Dict[str, Any]):
        output_prefix = json_output.with_suffix("")
        active_requested = bool(options.get("active"))

        def build_command(use_json_mode: bool, active_mode: bool) -> List[str]:
            command = [self.amass_path, "enum", "-d", target]
            if use_json_mode:
                command.extend(["-json", str(json_output)])
            else:
                command.extend(["-oA", str(output_prefix)])
            if active_mode:
                command.append("-active")
            return command

        attempts: List[Tuple[bool, bool]] = []
        attempts.append((True, active_requested))
        if active_requested:
            attempts.append((True, False))
        attempts.append((False, active_requested))
        if active_requested:
            attempts.append((False, False))

        last_result = None
        last_command: List[str] = []
        json_flag_supported = True

        for use_json_mode, active_mode in attempts:
            if use_json_mode and not json_flag_supported:
                continue

            command = build_command(use_json_mode, active_mode)
            result = self._execute_command(command, timeout=600)
            last_result = result
            last_command = command

            if result.returncode == 0:
                return result, command

            if use_json_mode and self._json_flag_unsupported(result):
                json_flag_supported = False
                self.logger.info(
                    "Amass does not support -json output flag, switching to -oA mode for {}",
                    target,
                )
                continue

            if active_mode:
                self.logger.warning("Amass active mode failed, retrying in passive mode for {}", target)

            has_json_file = self._resolve_amass_json_output(output_prefix, json_output) is not None
            has_stdout = bool((result.stdout or "").strip())
            if has_json_file or has_stdout:
                return result, command

        return last_result, last_command

    def _json_flag_unsupported(self, result) -> bool:
        combined_output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        patterns = [
            "flag provided but not defined: -json",
            "unknown flag: -json",
            "unknown option: -json",
            "no such option: -json",
        ]
        return any(pattern in combined_output for pattern in patterns)
    
    def parse_json_lines(self, json_file: Path) -> List[Finding]:
        """Parse Amass json API output"""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                        
                    data = json.loads(line)
                    name = data.get("name")
                    domain = data.get("domain")
                    
                    if not name:
                        continue
                        
                    finding = Finding(
                        title=f"Subdomain Keşfi: {name}",
                        description=f"{domain} domainine ait bir alt alan adı bulundu.",
                        risk_level=RiskLevel.INFO,
                        affected_url=name,
                        evidence=data,
                        recommendation="Keşfedilen bu varlıkların izole olduğundan ve gereksiz public erişimin kapalı olduğundan emin olun.",
                        verified=True
                    )
                    
                    findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse amass JSON lines: {e}")
            
        return findings

    def parse_text_output(self, raw_output: str, target: str) -> List[Finding]:
        """Fallback parser for Amass stdout when JSON file is not produced."""
        findings: List[Finding] = []
        if not raw_output:
            return findings

        cleaned_target = target.strip().lower()
        domain_pattern = re.compile(
            rf"\b([a-zA-Z0-9][a-zA-Z0-9._-]*\.{re.escape(cleaned_target)})\b",
            re.IGNORECASE,
        )

        seen = set()
        for match in domain_pattern.findall(raw_output):
            name = match.lower()
            if name in seen:
                continue
            seen.add(name)

            findings.append(
                Finding(
                    title=f"Subdomain Keşfi: {name}",
                    description=f"{cleaned_target} domainine ait bir alt alan adı bulundu.",
                    risk_level=RiskLevel.INFO,
                    affected_url=name,
                    evidence={"source": "stdout_fallback", "value": name},
                    recommendation="Keşfedilen bu varlıkların izole olduğundan ve gereksiz public erişimin kapalı olduğundan emin olun.",
                    verified=True,
                )
            )

        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        # Required by base but implemented via file in run() mostly
        return []
