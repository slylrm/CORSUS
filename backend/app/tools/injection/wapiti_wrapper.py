"""
Wapiti Wrapper - DAST and Black-box Fuzzer
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.tools.base import (
    BaseToolWrapper,
    Finding,
    RiskLevel,
    ToolCategory,
    ToolResult,
)


class WapitiWrapper(BaseToolWrapper):
    """Wapiti vulnerability fuzzer wrapper."""

    name = "wapiti"
    category = ToolCategory.INJECTION
    description = "Black-box web application vulnerability fuzzer"
    version = "3.1.6"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None, validate_binary: bool = True):
        self.config = config or {}
        self.validate_binary = validate_binary
        self.wapiti_path = self.config.get("path", getattr(settings, "WAPITI_PATH", "wapiti"))
        self.python_path = self.config.get("python_path", sys.executable)
        super().__init__(config=self.config)

    @staticmethod
    def _normalize_path(raw_path: Any) -> str:
        return str(raw_path or "").strip().strip('"').strip("'")

    def _resolve_python_path(self) -> Optional[str]:
        def _is_windows_store_alias(path_value: str) -> bool:
            try:
                normalized = str(path_value or "").lower()
                return "\\windowsapps\\" in normalized and normalized.endswith(".exe")
            except Exception:
                return False

        normalized = self._normalize_path(self.python_path)
        if normalized:
            candidate = Path(normalized)
            if candidate.is_file():
                if not _is_windows_store_alias(str(candidate)):
                    return str(candidate)
            resolved = shutil.which(normalized)
            if resolved and not _is_windows_store_alias(resolved):
                return resolved

        if sys.executable and not _is_windows_store_alias(sys.executable):
            return sys.executable

        return None

    def _build_pythonpath(self, extra_paths: List[str]) -> str:
        env_paths: List[str] = []
        for value in extra_paths:
            normalized = self._normalize_path(value)
            if normalized:
                env_paths.append(normalized)

        venv_site = Path(self.python_path).resolve().parent.parent / "Lib" / "site-packages"
        if venv_site.is_dir():
            env_paths.append(str(venv_site))

        existing = os.environ.get("PYTHONPATH", "")
        if existing:
            env_paths.append(existing)

        return os.pathsep.join(env_paths)

    def _resolve_wapiti_path(self) -> Optional[str]:
        normalized = self._normalize_path(self.wapiti_path)
        candidates: List[Path] = []

        if normalized:
            configured_candidate = Path(normalized)
            candidates.append(configured_candidate)
            if configured_candidate.is_dir():
                candidates.extend(
                    [
                        configured_candidate / "bin" / "wapiti",
                        configured_candidate / "bin" / "wapiti.py",
                        configured_candidate / "wapiti",
                        configured_candidate / "wapiti.py",
                    ]
                )

        bundled_wapiti = Path(__file__).resolve().parents[2] / "bin" / "wapiti"
        candidates.extend(
            [
                bundled_wapiti,
                bundled_wapiti / "bin" / "wapiti",
                bundled_wapiti / "bin" / "wapiti.py",
                bundled_wapiti / "wapiti",
                bundled_wapiti / "wapiti.py",
            ]
        )

        project_root = Path(__file__).resolve().parents[4]
        for external_root in (
            project_root / "niktowap",
            project_root.parent / "niktowap",
            project_root / "nikto wap",
            project_root.parent / "nikto wap",
        ):
            candidates.extend(
                [
                    external_root / "wapiti-master",
                    external_root / "wapiti-master" / "bin" / "wapiti",
                    external_root / "wapiti-master" / "bin" / "wapiti.py",
                ]
            )

        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
            if candidate.is_dir():
                for script_path in (
                    candidate / "bin" / "wapiti",
                    candidate / "bin" / "wapiti.py",
                    candidate / "wapiti",
                    candidate / "wapiti.py",
                ):
                    if script_path.is_file():
                        return str(script_path)

        command_name = normalized or "wapiti"
        resolved = shutil.which(command_name)
        if resolved:
            return resolved
        if command_name.lower() != "wapiti":
            fallback = shutil.which("wapiti")
            if fallback:
                return fallback
        return None

    @staticmethod
    def _requires_python_launcher(path_value: str) -> bool:
        candidate = Path(path_value)
        if not candidate.is_file():
            return False
        return candidate.suffix.lower() not in {".exe", ".bat", ".cmd", ".com", ".ps1"}

    def _validate_dependencies(self):
        if not getattr(self, "validate_binary", True):
            return

        resolved_wapiti = self._resolve_wapiti_path()
        if not resolved_wapiti:
            raise RuntimeError("wapiti is not installed")

        self.wapiti_path = resolved_wapiti

        if self._requires_python_launcher(resolved_wapiti):
            resolved_python = self._resolve_python_path()
            if not resolved_python:
                raise RuntimeError("python is required to run the wapiti script")
            self.python_path = resolved_python

            # Preflight import check for external Wapiti runtime dependencies.
            script_path = Path(resolved_wapiti)
            wapiti_root = script_path.parent.parent
            env = os.environ.copy()
            env["PYTHONPATH"] = self._build_pythonpath([str(wapiti_root)])
            check_cmd = [str(self.python_path), "-X", "utf8", "-c", "import wapitiCore.main.wapiti"]
            check = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                cwd=str(wapiti_root),
                env=env,
                timeout=20,
            )
            if check.returncode != 0:
                missing = ""
                if "ModuleNotFoundError:" in (check.stderr or ""):
                    missing = (check.stderr or "").split("ModuleNotFoundError:", 1)[-1].strip()
                detail = missing or (check.stderr or check.stdout or "unknown import error").strip()
                raise RuntimeError(f"wapiti runtime dependencies missing ({detail})")

    def _build_command(self, target: str, opts: Dict[str, Any], output_file: Path) -> List[str]:
        resolved_wapiti = self._resolve_wapiti_path()
        if not resolved_wapiti:
            if getattr(self, "validate_binary", True):
                raise RuntimeError("wapiti launcher could not be resolved")
            resolved_wapiti = self._normalize_path(self.wapiti_path) or "wapiti"

        self.wapiti_path = resolved_wapiti
        command: List[str]
        if self._requires_python_launcher(resolved_wapiti):
            resolved_python = self._resolve_python_path()
            if not resolved_python:
                if getattr(self, "validate_binary", True):
                    raise RuntimeError("python is required to run the wapiti script")
                resolved_python = self._normalize_path(self.python_path)
                if not resolved_python:
                    raise RuntimeError("python is required to run the wapiti script")
            self.python_path = resolved_python
            # Force UTF-8 stdio to avoid Windows codepage crashes in banner printing.
            command = [str(self.python_path), "-X", "utf8", str(resolved_wapiti)]
        else:
            command = [str(resolved_wapiti)]

        command.extend(
            [
                "-u",
                target,
                "-f",
                "json",
                "-o",
                str(output_file),
                "--max-scan-time",
                str(int(opts.get("max_scan_time", 300))),
                "--flush-session",
            ]
        )

        if opts.get("deep_scan", False):
            command.extend(["-d", "10"])

        return command

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = time.time()
        timestamp = datetime.now(timezone.utc)

        json_output = (settings.WAPITI_OUTPUT_DIR / f"wapiti_{datetime.now().timestamp()}.json").resolve()
        json_output.parent.mkdir(parents=True, exist_ok=True)

        command = self._build_command(target, opts, output_file=json_output)
        timeout = int(opts.get("tool_timeout", 900))

        findings: List[Finding] = []
        errors: List[str] = []
        raw_output = ""

        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = self._build_pythonpath([str(Path(self.wapiti_path).resolve().parent.parent)])

            command_cwd = None
            if self._requires_python_launcher(resolved_wapiti := self.wapiti_path):
                command_cwd = str(Path(resolved_wapiti).resolve().parent.parent)

            result = self._execute_command(command, timeout=timeout, cwd=command_cwd, env=env)
            stdout = getattr(result, "stdout", "") or ""
            stderr = getattr(result, "stderr", "") or ""
            return_code = int(getattr(result, "returncode", 0) or 0)
            raw_output = stdout + stderr

            if json_output.exists():
                findings = self.parse_json_output(json_output)

            if return_code != 0 and not findings:
                error_detail = stderr.strip() or stdout.strip() or f"Exit code {return_code}"
                errors.append(error_detail[:500])

            success = (return_code == 0 and not errors) or bool(findings)
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Wapiti execution failed", exc_info=True)
            findings = []
            success = False
            errors.append(str(exc))

        duration = time.time() - start_ts

        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=timestamp,
            duration=duration,
            success=success,
            findings=[f.to_dict() for f in findings],
            raw_output=raw_output,
            errors=errors,
            metadata={
                "command": " ".join(command),
                "output_file": str(json_output),
                "execution_mode": "python_script" if self._requires_python_launcher(self.wapiti_path) else "direct",
            },
            exit_code=0 if success else 1,
            stdout=raw_output,
            stderr="; ".join(errors),
        )

    def parse_json_output(self, json_file: Path) -> List[Finding]:
        """Parse Wapiti JSON output."""
        findings: List[Finding] = []

        try:
            with open(json_file, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)

            classifications = data.get("classifications", {})
            vulnerabilities = data.get("vulnerabilities", {})

            for vuln_type, vuln_list in vulnerabilities.items():
                for vuln in vuln_list:
                    classification = classifications.get(vuln_type, {})
                    title = classification.get("title", vuln_type)
                    description = classification.get("desc", "-")
                    recommendation = classification.get("sol", "-")

                    level = vuln.get("level", 1)
                    risk_mapping = {
                        1: RiskLevel.LOW,
                        2: RiskLevel.MEDIUM,
                        3: RiskLevel.HIGH,
                        4: RiskLevel.CRITICAL,
                    }
                    risk_level = risk_mapping.get(level, RiskLevel.INFO)

                    finding = Finding(
                        title=title,
                        description=description,
                        risk_level=risk_level,
                        affected_url=vuln.get("path", ""),
                        evidence={
                            "method": vuln.get("method"),
                            "parameter": vuln.get("parameter"),
                            "info": vuln.get("info"),
                            "timeout": vuln.get("timeout", False),
                            "curl_command": vuln.get("curl_command", ""),
                        },
                        recommendation=recommendation,
                        verified=True,
                    )
                    findings.append(finding)
        except Exception as exc:  # noqa: BLE001
            self.logger.error(f"Failed to parse wapiti JSON: {exc}")

        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        return []
