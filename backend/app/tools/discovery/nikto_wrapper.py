"""
Nikto Wrapper - Web Server Misconfiguration Scanner
Production-ready tool wrapper compatible with ScannerEngine/ToolRunner.
"""

import json
import subprocess
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory,
)
from app.config import settings
from app.utils.logger import logger


class NiktoWrapper(BaseToolWrapper):
    """Nikto tool wrapper (technology/misconfiguration discovery)."""

    name = "nikto"
    category = ToolCategory.DISCOVERY
    description = "Nikto web server scanner"
    version = "2.5.x"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None, validate_binary: bool = True):
        self.config = config or {}
        self.validate_binary = validate_binary
        self.nikto_path = self.config.get("path", getattr(settings, "NIKTO_PATH", "nikto"))
        self.perl_path = self.config.get("perl_path", getattr(settings, "PERL_PATH", "perl"))
        super().__init__(config=self.config)

    @staticmethod
    def _normalize_path(raw_path: Any) -> str:
        return str(raw_path or "").strip().strip('"').strip("'")

    def _resolve_perl_path(self) -> Optional[str]:
        normalized = self._normalize_path(self.perl_path)
        if not normalized:
            return None
        candidate = Path(normalized)
        if candidate.is_file():
            return str(candidate)
        resolved = shutil.which(normalized)
        if resolved:
            return resolved
        return None

    def _resolve_nikto_path(self) -> Optional[str]:
        normalized = self._normalize_path(self.nikto_path)

        candidates: List[Path] = []
        if normalized:
            candidate = Path(normalized)
            candidates.append(candidate)
            if candidate.is_dir():
                candidates.extend(
                    [
                        candidate / "program" / "nikto.pl",
                        candidate / "nikto.pl",
                    ]
                )

        bundled_nikto = Path(__file__).resolve().parents[2] / "bin" / "nikto"
        candidates.extend(
            [
                bundled_nikto / "program" / "nikto.pl",
                bundled_nikto / "nikto.pl",
            ]
        )

        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)

        command_name = normalized or "nikto"
        resolved = shutil.which(command_name)
        if resolved:
            return resolved
        if command_name.lower() != "nikto":
            fallback = shutil.which("nikto")
            if fallback:
                return fallback
        return None

    def _validate_dependencies(self):
        if not getattr(self, "validate_binary", True):
            return
        resolved_nikto = self._resolve_nikto_path()
        if not resolved_nikto:
            git_source = self._resolve_nikto_git_source()
            if not git_source:
                raise RuntimeError("nikto is not installed")
            resolved_perl = self._resolve_perl_path()
            if not resolved_perl:
                raise RuntimeError("perl is required to run nikto via git-stream fallback")
            self.perl_path = resolved_perl
            logger.warning("Nikto launcher is not directly accessible; using git-stream fallback from {}", git_source)
            return

        self.nikto_path = resolved_nikto
        nikto_candidate = Path(resolved_nikto)

        if nikto_candidate.suffix.lower() == ".pl":
            resolved_perl = self._resolve_perl_path()
            if not resolved_perl:
                raise RuntimeError("perl is required to run nikto.pl")
            self.perl_path = resolved_perl

            if self._is_corrupted_perl_script(nikto_candidate):
                git_source = self._resolve_nikto_git_source()
                if not git_source:
                    raise RuntimeError(f"Nikto script appears corrupted: {nikto_candidate}")
                logger.warning(
                    "Nikto script is not readable; using git-stream fallback from {}",
                    git_source,
                )
            return

        return super()._validate_dependencies()

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = time.time()
        request_timeout = int(opts.get("timeout", 20))
        command_timeout = int(opts.get("tool_timeout", max(request_timeout * 6, 120)))
        nikto_output_file = (settings.NIKTO_OUTPUT_DIR / f"nikto_{datetime.now().timestamp()}.json").resolve()
        nikto_output_file.parent.mkdir(parents=True, exist_ok=True)

        command = self._build_command(target, opts, output_file=nikto_output_file)
        errors: List[str] = []

        try:
            result = self._execute_command(command, timeout=command_timeout)
            stdout = getattr(result, "stdout", "") or ""
            stderr = getattr(result, "stderr", "") or ""
            return_code = int(getattr(result, "returncode", 0) or 0)

            file_output = ""
            if nikto_output_file.exists():
                try:
                    file_output = nikto_output_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    file_output = ""

            raw_output = stdout + stderr
            has_file_output = bool(file_output.strip())
            timed_out = return_code == -1 and "timed out" in stderr.lower()

            parse_source = ""
            if has_file_output:
                parse_source = file_output
            elif return_code == 0 and raw_output.strip():
                parse_source = raw_output

            findings = [
                f.to_dict() if isinstance(f, Finding) else f
                for f in self.parse_output(parse_source, target)
            ] if parse_source.strip() else []

            if has_file_output:
                raw_output = f"{raw_output}\n{file_output}" if raw_output else file_output

            if timed_out and not has_file_output:
                errors.append(f"Nikto timed out after {command_timeout}s with no parsable output")
            elif return_code != 0:
                error_detail = stderr.strip() or stdout.strip() or f"Exit code {return_code}"
                errors.append(error_detail[:500])

            if return_code == 0 and not findings and not raw_output.strip():
                errors.append("Nikto produced no output; check nikto.pl integrity and runtime dependencies")

            success = (return_code == 0 and not errors) or (bool(findings) and not timed_out)
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
            metadata={
                "command": " ".join(command),
                "output_file": str(nikto_output_file),
                "execution_mode": "git_stream" if self._is_git_stream_command(command) else "direct",
                "request_timeout": request_timeout,
                "command_timeout": command_timeout,
            },
            exit_code=0 if success else 1,
            stdout=raw_output,
            stderr="; ".join(errors),
        )

    def _build_command(self, target: str, opts: Dict[str, Any], output_file: Optional[Path] = None) -> List[str]:
        resolved_nikto = self._resolve_nikto_path()
        output_arg = str(output_file) if output_file is not None else "-"
        max_runtime_seconds = self._resolve_max_runtime_seconds(opts)

        if not resolved_nikto:
            git_source = self._resolve_nikto_git_source()
            if git_source:
                return self._build_git_stream_command(git_source, target, opts, output_arg)
            if getattr(self, "validate_binary", True):
                raise RuntimeError("nikto launcher could not be resolved")
            resolved_nikto = self._normalize_path(self.nikto_path) or "nikto"

        self.nikto_path = resolved_nikto
        nikto_candidate = Path(resolved_nikto)

        if nikto_candidate.suffix.lower() == ".pl":
            if self._is_corrupted_perl_script(nikto_candidate):
                git_source = self._resolve_nikto_git_source()
                if not git_source:
                    raise RuntimeError(f"Nikto script appears corrupted: {nikto_candidate}")
                return self._build_git_stream_command(git_source, target, opts, output_arg)

            resolved_perl = self._resolve_perl_path()
            if not resolved_perl:
                if getattr(self, "validate_binary", True):
                    raise RuntimeError("perl is required to run nikto.pl")
                resolved_perl = self._normalize_path(self.perl_path) or "perl"
            self.perl_path = resolved_perl
            command = [str(self.perl_path), str(nikto_candidate), "-h", target, "-Format", "json", "-output", output_arg]
        else:
            command = [str(self.nikto_path), "-h", target, "-Format", "json", "-output", output_arg]

        if opts.get("port"):
            command.extend(["-port", str(opts["port"])])
        if opts.get("ssl"):
            command.append("-ssl")
        if opts.get("plugins"):
            command.extend(["-Plugins", str(opts["plugins"])])
        if opts.get("timeout"):
            command.extend(["-timeout", str(int(opts["timeout"]))])
        if max_runtime_seconds:
            command.extend(["-maxtime", f"{max_runtime_seconds}s"])

        return command

    def _resolve_max_runtime_seconds(self, opts: Dict[str, Any]) -> Optional[int]:
        max_runtime = opts.get("max_runtime")
        if max_runtime is None and opts.get("tool_timeout"):
            try:
                # Keep Nikto's own runtime cap slightly below subprocess timeout.
                max_runtime = max(60, int(opts["tool_timeout"]) - 30)
            except (TypeError, ValueError):
                max_runtime = None

        if max_runtime is None:
            return None

        try:
            return max(60, int(max_runtime))
        except (TypeError, ValueError):
            return None

    def _is_corrupted_perl_script(self, script_path: Path) -> bool:
        try:
            sample = script_path.read_bytes()[:4096]
        except Exception:
            return True

        if not sample:
            return True

        # Perl text files should never contain NUL bytes in the header block.
        if b"\x00" in sample:
            return True

        text_preview = sample.decode("utf-8", errors="ignore").strip().lower()
        if not text_preview:
            return True

        return not ("perl" in text_preview or "nikto" in text_preview)

    def _resolve_nikto_git_source(self) -> Optional[Path]:
        candidates: List[Path] = []

        explicit_source = self._normalize_path(self.config.get("nikto_git_source"))
        if explicit_source:
            candidates.append(Path(explicit_source))

        nikto_candidate = Path(self._normalize_path(self.nikto_path))
        if nikto_candidate.parts:
            if nikto_candidate.is_file():
                try:
                    bin_dir = nikto_candidate.parents[2]
                    candidates.extend(sorted(bin_dir.glob("nikto_backup_*"), reverse=True))
                except Exception:
                    pass
            elif nikto_candidate.is_dir():
                candidates.extend(sorted(nikto_candidate.glob("nikto_backup_*"), reverse=True))

        bundled_bin = Path(__file__).resolve().parents[2] / "bin"
        if bundled_bin.is_dir():
            candidates.extend(sorted(bundled_bin.glob("nikto_backup_*"), reverse=True))

        seen: set[str] = set()
        for candidate in candidates:
            try:
                normalized = str(candidate.resolve())
            except Exception:
                normalized = str(candidate)
            if normalized in seen:
                continue
            seen.add(normalized)

            if (candidate / ".git").exists():
                return candidate

        return None

    def _build_git_stream_command(
        self,
        source_repo: Path,
        target: str,
        opts: Dict[str, Any],
        output_arg: str,
    ) -> List[str]:
        resolved_perl = self._resolve_perl_path()
        if not resolved_perl:
            if getattr(self, "validate_binary", True):
                raise RuntimeError("perl is required to run nikto.pl")
            resolved_perl = self._normalize_path(self.perl_path) or "perl"
        self.perl_path = resolved_perl

        nikto_args: List[str] = []
        config_file = source_repo / "program" / "nikto.conf.default"
        if config_file.exists():
            nikto_args.extend(["-config", str(config_file)])

        nikto_args.extend(["-h", target, "-Format", "json", "-output", output_arg])
        if opts.get("port"):
            nikto_args.extend(["-port", str(opts["port"])])
        if opts.get("ssl"):
            nikto_args.append("-ssl")
        if opts.get("plugins"):
            nikto_args.extend(["-Plugins", str(opts["plugins"])])
        if opts.get("timeout"):
            nikto_args.extend(["-timeout", str(int(opts["timeout"]))])
        max_runtime_seconds = self._resolve_max_runtime_seconds(opts)
        if max_runtime_seconds:
            nikto_args.extend(["-maxtime", f"{max_runtime_seconds}s"])

        program_dir = source_repo / "program"
        git_cmd = subprocess.list2cmdline(["git", "-C", str(source_repo), "show", "HEAD:program/nikto.pl"])
        perl_cmd = subprocess.list2cmdline([str(self.perl_path), "-", *nikto_args])
        prelude = f"cd /d {subprocess.list2cmdline([str(program_dir)])} & " if program_dir.exists() else ""
        return ["cmd", "/c", f"{prelude}{git_cmd} | {perl_cmd}"]

    @staticmethod
    def _is_git_stream_command(command: List[str]) -> bool:
        return bool(command and command[0].lower() == "cmd" and any("HEAD:program/nikto.pl" in part for part in command))

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
