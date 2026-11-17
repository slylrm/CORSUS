"""
Nuclei Wrapper - Template-based Vulnerability Scanner
"""

from typing import Dict, List, Any, Optional
import json
import time
from datetime import datetime
from pathlib import Path
import shutil
import subprocess

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.config import settings
from app.config import PROJECT_ROOT

class NucleiWrapper(BaseToolWrapper):
    """
    Nuclei vulnerability scanner wrapper
    """
    
    name = "nuclei"
    category = ToolCategory.DISCOVERY
    description = "Template-based fast vulnerability scanner"
    version = "3.1"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.nuclei_path = config.get("path", getattr(settings, "NUCLEI_PATH", "nuclei")) if config else getattr(settings, "NUCLEI_PATH", "nuclei")
        # Resolve bare command names to absolute paths when possible to avoid Windows alias popups
        try:
            if self.nuclei_path and not Path(self.nuclei_path).is_file():
                resolved = shutil.which(str(self.nuclei_path))
                if resolved:
                    self.nuclei_path = resolved
            # Fallback to bundled binary in backend/app/bin if present
            if (not Path(self.nuclei_path).is_file()):
                bundled = Path(PROJECT_ROOT) / "backend" / "app" / "bin" / "nuclei.exe"
                if bundled.exists():
                    self.nuclei_path = str(bundled)
            # Probe supported flags from help output (best-effort, short timeout)
            self._json_export_flag = "-json-export"
            self._jsonl_flag = "-j"
            try:
                probe = subprocess.run([self.nuclei_path, "-h"], capture_output=True, text=True, timeout=3)
                help_text = (probe.stdout or "") + "\n" + (probe.stderr or "")
                help_text = help_text.lower()
                if "-je" in help_text and "json-export" in help_text:
                    # both shown; prefer the canonical long form
                    self._json_export_flag = "-json-export"
                elif "-je" in help_text:
                    self._json_export_flag = "-je"
                elif "json-export" in help_text:
                    self._json_export_flag = "-json-export"

                if "-j, -jsonl" in help_text or "-jsonl" in help_text or "-j\n" in help_text:
                    self._jsonl_flag = "-j"
                elif "jsonl" in help_text:
                    self._jsonl_flag = "-jsonl"
            except Exception:
                # Best-effort probe; fall back to defaults on failure
                pass
        except Exception:
            pass
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Nuclei çalıştır
        """
        start_time = datetime.now()
        options = options or {}
        try:
            timeout = max(30, int(options.get("timeout", 180)))
        except (TypeError, ValueError):
            timeout = 180
        try:
            total_budget = max(timeout, int(options.get("tool_timeout", timeout)))
        except (TypeError, ValueError):
            total_budget = timeout
        
        # JSONL output için (canonical path from settings)
        json_output = settings.NUCLEI_OUTPUT_DIR / f"nuclei_{datetime.now().timestamp()}.json"
        json_output.parent.mkdir(parents=True, exist_ok=True)

        # Use conservative defaults to avoid thread exhaustion on Windows hosts.
        concurrency = max(1, int(options.get("concurrency", 5)))
        rate_limit = max(1, int(options.get("rate_limit", 20)))
        bulk_size = max(1, int(options.get("bulk_size", 5)))
        retries = max(0, int(options.get("retries", 0)))
        retry_opaque_exit = bool(options.get("retry_opaque_exit", True))
        retry_on_timeout = bool(options.get("retry_on_timeout", False))
        hard_stability_retry = bool(options.get("hard_stability_retry", True))
        hard_retry_tags = str(options.get("hard_retry_tags", "cve,misconfig,exposure")).strip()
        no_interactsh = bool(options.get("no_interactsh", True))
        disable_update_check = bool(options.get("disable_update_check", True))
        request_timeout = max(1, int(options.get("request_timeout", 10)))
        headless_concurrency = max(1, int(options.get("headless_concurrency", 2)))
        headless_bulk_size = max(1, int(options.get("headless_bulk_size", 2)))
        payload_concurrency = max(1, int(options.get("payload_concurrency", 4)))

        current_concurrency = concurrency
        current_rate_limit = rate_limit
        current_bulk_size = bulk_size
        current_retries = retries
        current_request_timeout = request_timeout
        current_headless_concurrency = headless_concurrency
        current_headless_bulk_size = headless_bulk_size
        current_payload_concurrency = payload_concurrency

        # Quick mode reduces limits to make a short, conservative run for diagnostics
        if bool(options.get("quick", False)):
            current_concurrency = 1
            current_rate_limit = max(1, min(current_rate_limit, 5))
            current_bulk_size = 1
            current_retries = 0
            current_request_timeout = max(1, min(current_request_timeout, 5))

        command = self._build_command(
            target=target,
            json_output=json_output,
            options=options,
            concurrency=current_concurrency,
            rate_limit=current_rate_limit,
            bulk_size=current_bulk_size,
            retries=current_retries,
            no_interactsh=no_interactsh,
            disable_update_check=disable_update_check,
            request_timeout=current_request_timeout,
            headless_concurrency=current_headless_concurrency,
            headless_bulk_size=current_headless_bulk_size,
            payload_concurrency=current_payload_concurrency,
        )
            
        findings = []
        errors = []
        raw_output = ""
        success = False
        
        try:
            run_started = time.monotonic()
            first_attempt_timeout = timeout
            if retry_on_timeout:
                first_attempt_timeout = min(timeout, max(30, total_budget - 90))

            result = self._execute_command(command, timeout=first_attempt_timeout)
            # If nuclei reports missing templates, try a one-shot update and retry once.
            raw_text_tmp = ((result.stdout or "") + (result.stderr or "")).lower()
            if "no templates provided" in raw_text_tmp or "no templates found" in raw_text_tmp:
                try:
                    self.logger.info("Nuclei reported missing templates; attempting 'nuclei -ut' to update templates (short, best-effort)")
                    _ = self._execute_command([self.nuclei_path, "-ut"], timeout=60)
                    # retry main command once with slightly increased timeout
                    result = self._execute_command(command, timeout=min(total_budget, max(60, first_attempt_timeout)))
                    raw_output = (result.stdout or "") + (result.stderr or "")
                except Exception:
                    pass
            raw_output = (result.stdout or "") + (result.stderr or "")
            timed_out = self._is_timeout_result(result)

            # If nuclei wrote JSON to stdout instead of the export file, persist it
            try:
                if (not json_output.exists() or json_output.stat().st_size == 0) and (result.stdout or ""):
                    # Attempt to decode and write stdout to json_output
                    try:
                        data_bytes = result.stdout if isinstance(result.stdout, (bytes, bytearray)) else str(result.stdout).encode('utf-8')
                        text = data_bytes.decode('utf-8', errors='replace') if isinstance(data_bytes, (bytes, bytearray)) else str(result.stdout)
                    except Exception:
                        text = str(result.stdout or "")

                    if text.strip():
                        try:
                            json_output.write_text(text, encoding='utf-8')
                        except Exception:
                            # best-effort, ignore write errors and continue
                            pass
            except Exception:
                pass

            # Timeout retries are opt-in. Default is off to avoid long hanging retries.
            if timed_out and retry_on_timeout:
                fallback_concurrency = min(current_concurrency, 3)
                fallback_rate_limit = min(current_rate_limit, 10)
                fallback_bulk_size = min(current_bulk_size, 3)
                fallback_request_timeout = min(current_request_timeout, 10)
                fallback_headless_concurrency = min(current_headless_concurrency, 2)
                fallback_headless_bulk_size = min(current_headless_bulk_size, 2)
                fallback_payload_concurrency = min(current_payload_concurrency, 2)
                fallback_retries = 0

                fallback_command = self._build_command(
                    target=target,
                    json_output=json_output,
                    options=options,
                    concurrency=fallback_concurrency,
                    rate_limit=fallback_rate_limit,
                    bulk_size=fallback_bulk_size,
                    retries=fallback_retries,
                    no_interactsh=no_interactsh,
                    disable_update_check=disable_update_check,
                    request_timeout=fallback_request_timeout,
                    headless_concurrency=fallback_headless_concurrency,
                    headless_bulk_size=fallback_headless_bulk_size,
                    payload_concurrency=fallback_payload_concurrency,
                )

                remaining_budget = int(total_budget - (time.monotonic() - run_started) - 10)
                if remaining_budget >= 60:
                    retry_timeout = min(max(remaining_budget, 60), 900)
                    self.logger.warning(
                        "Nuclei timed out after {}s, retrying once with safer limits (-c {}, -rl {}, -bs {}, -retries {}, -timeout {}) and {}s process timeout",
                        first_attempt_timeout,
                        fallback_concurrency,
                        fallback_rate_limit,
                        fallback_bulk_size,
                        fallback_retries,
                        fallback_request_timeout,
                        retry_timeout,
                    )
                    result = self._execute_command(fallback_command, timeout=retry_timeout)
                    raw_output = (result.stdout or "") + (result.stderr or "")
                    command = fallback_command
                    current_concurrency = fallback_concurrency
                    current_rate_limit = fallback_rate_limit
                    current_bulk_size = fallback_bulk_size
                    current_retries = fallback_retries
                    current_request_timeout = fallback_request_timeout
                    current_headless_concurrency = fallback_headless_concurrency
                    current_headless_bulk_size = fallback_headless_bulk_size
                    current_payload_concurrency = fallback_payload_concurrency
                    timed_out = self._is_timeout_result(result)
                else:
                    self.logger.warning(
                        "Nuclei timed out after {}s and remaining tool timeout budget ({}s) is insufficient for retry",
                        first_attempt_timeout,
                        max(0, remaining_budget),
                    )
            elif timed_out:
                self.logger.warning("Nuclei timed out after {}s (timeout retry disabled)", first_attempt_timeout)

            if result.returncode != 0 and (not timed_out) and self._needs_reduced_limits_retry(
                raw_output,
                result.returncode,
                retry_opaque_exit=retry_opaque_exit,
            ):
                fallback_concurrency = min(current_concurrency, 5)
                fallback_rate_limit = min(current_rate_limit, 20)
                fallback_bulk_size = min(current_bulk_size, 5)
                fallback_retries = 0
                fallback_request_timeout = min(current_request_timeout, 10)
                fallback_headless_concurrency = min(current_headless_concurrency, 2)
                fallback_headless_bulk_size = min(current_headless_bulk_size, 2)
                fallback_payload_concurrency = min(current_payload_concurrency, 2)

                limits_tightened = (
                    fallback_concurrency < current_concurrency
                    or fallback_rate_limit < current_rate_limit
                    or fallback_bulk_size < current_bulk_size
                    or fallback_request_timeout < current_request_timeout
                    or fallback_headless_concurrency < current_headless_concurrency
                    or fallback_headless_bulk_size < current_headless_bulk_size
                    or fallback_payload_concurrency < current_payload_concurrency
                )

                if limits_tightened:
                    self.logger.warning(
                        "Nuclei runtime instability detected, retrying with reduced limits (-c {}, -rl {}, -bs {}, -retries {}, -timeout {}, -headc {}, -hbs {}, -pc {})",
                        fallback_concurrency,
                        fallback_rate_limit,
                        fallback_bulk_size,
                        fallback_retries,
                        fallback_request_timeout,
                        fallback_headless_concurrency,
                        fallback_headless_bulk_size,
                        fallback_payload_concurrency,
                    )
                    fallback_command = self._build_command(
                        target=target,
                        json_output=json_output,
                        options=options,
                        concurrency=fallback_concurrency,
                        rate_limit=fallback_rate_limit,
                        bulk_size=fallback_bulk_size,
                        retries=fallback_retries,
                        no_interactsh=no_interactsh,
                        disable_update_check=disable_update_check,
                        request_timeout=fallback_request_timeout,
                        headless_concurrency=fallback_headless_concurrency,
                        headless_bulk_size=fallback_headless_bulk_size,
                        payload_concurrency=fallback_payload_concurrency,
                    )
                    retry_timeout = min(max(timeout, 240), 900)
                    result = self._execute_command(fallback_command, timeout=retry_timeout)
                    raw_output = (result.stdout or "") + (result.stderr or "")
                    command = fallback_command
                    current_concurrency = fallback_concurrency
                    current_rate_limit = fallback_rate_limit
                    current_bulk_size = fallback_bulk_size
                    current_retries = fallback_retries
                    current_request_timeout = fallback_request_timeout
                    current_headless_concurrency = fallback_headless_concurrency
                    current_headless_bulk_size = fallback_headless_bulk_size
                    current_payload_concurrency = fallback_payload_concurrency
                    timed_out = self._is_timeout_result(result)

            if (
                hard_stability_retry
                and result.returncode != 0
                and (not timed_out)
                and not findings
                and self._needs_hard_stability_retry(raw_output, result.returncode)
            ):
                hard_concurrency = 1
                hard_rate_limit = min(current_rate_limit, 5)
                hard_bulk_size = 1
                hard_retries = 0
                hard_request_timeout = min(current_request_timeout, 8)
                hard_headless_concurrency = 1
                hard_headless_bulk_size = 1
                hard_payload_concurrency = 1

                hard_options = dict(options)
                hard_options["automatic_scan"] = False
                if hard_retry_tags and not hard_options.get("tags"):
                    hard_options["tags"] = hard_retry_tags

                hard_command = self._build_command(
                    target=target,
                    json_output=json_output,
                    options=hard_options,
                    concurrency=hard_concurrency,
                    rate_limit=hard_rate_limit,
                    bulk_size=hard_bulk_size,
                    retries=hard_retries,
                    no_interactsh=no_interactsh,
                    disable_update_check=disable_update_check,
                    request_timeout=hard_request_timeout,
                    headless_concurrency=hard_headless_concurrency,
                    headless_bulk_size=hard_headless_bulk_size,
                    payload_concurrency=hard_payload_concurrency,
                )

                remaining_budget = int(total_budget - (time.monotonic() - run_started) - 5)
                if remaining_budget >= 45:
                    hard_retry_timeout = min(max(remaining_budget, 45), 300)
                    self.logger.warning(
                        "Nuclei exited in unstable/no-output state, retrying with hard-safe profile (-c {}, -rl {}, -bs {}, -retries {}, -headc {}, -hbs {}, -pc {}, -as disabled{})",
                        hard_concurrency,
                        hard_rate_limit,
                        hard_bulk_size,
                        hard_retries,
                        hard_headless_concurrency,
                        hard_headless_bulk_size,
                        hard_payload_concurrency,
                        f", -tags {hard_options.get('tags')}" if hard_options.get("tags") else "",
                    )
                    result = self._execute_command(hard_command, timeout=hard_retry_timeout)
                    raw_output = (result.stdout or "") + (result.stderr or "")
                    command = hard_command
                    timed_out = self._is_timeout_result(result)
                    if json_output.exists():
                        findings = self.parse_json_output(json_output)
                else:
                    self.logger.warning(
                        "Nuclei hard-safe retry skipped due to insufficient remaining tool timeout budget ({}s)",
                        max(0, remaining_budget),
                    )

            if json_output.exists():
                findings = self.parse_json_output(json_output)

            # Ensure downstream components always get a non-empty JSON artifact.
            if not findings:
                # Do not launch a second scan solely to recover output: that would
                # bypass the selected limits, timeout budget, and cancellation state.
                self._ensure_json_output_file(json_output)

            if result.returncode != 0:
                if not (result.stderr or "").strip() and not (result.stdout or "").strip() and not findings:
                    error_detail = f"Nuclei exited with code {result.returncode} and produced no output"
                else:
                    error_detail = (result.stderr or "").strip() or (result.stdout or "").strip() or f"Exit code {result.returncode}"
                errors.append(error_detail[:1000])

            success = (result.returncode == 0) or (len(findings) > 0)

        except Exception as e:
            self.logger.error(f"Nuclei execution failed: {e}")
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
            metadata={
                "command": " ".join(command),
                "timeout": timeout,
                "tool_timeout": total_budget,
                "retry_opaque_exit": retry_opaque_exit,
                "retry_on_timeout": retry_on_timeout,
                "hard_stability_retry": hard_stability_retry,
                "no_interactsh": no_interactsh,
                "disable_update_check": disable_update_check,
                "request_timeout": request_timeout,
                "headless_concurrency": headless_concurrency,
                "headless_bulk_size": headless_bulk_size,
                "payload_concurrency": payload_concurrency,
                "json_output": str(json_output),
            }
        )

    def _is_timeout_result(self, result: Any) -> bool:
        stderr_text = (getattr(result, "stderr", "") or "").lower()
        return getattr(result, "returncode", 0) == -1 and "timed out" in stderr_text

    def _ensure_json_output_file(self, json_output: Path) -> None:
        try:
            if (not json_output.exists()) or json_output.stat().st_size == 0:
                json_output.write_text("[]\n", encoding="utf-8")
        except Exception as e:
            self.logger.debug("Could not ensure nuclei output file {}: {}", json_output, e)

    def _build_command(
        self,
        target: str,
        json_output: Path,
        options: Dict[str, Any],
        concurrency: int,
        rate_limit: int,
        bulk_size: int,
        retries: int,
        no_interactsh: bool,
        disable_update_check: bool,
        request_timeout: int,
        headless_concurrency: int,
        headless_bulk_size: int,
        payload_concurrency: int,
    ) -> List[str]:
        command = [
            self.nuclei_path,
            "-u", target,
            self._json_export_flag, str(json_output),
            "-silent",
            "-c", str(concurrency),
            "-rl", str(rate_limit),
            "-bs", str(bulk_size),
            "-retries", str(retries),
            "-timeout", str(request_timeout),
            "-headc", str(headless_concurrency),
            "-hbs", str(headless_bulk_size),
            "-pc", str(payload_concurrency),
        ]

        if disable_update_check:
                command.append("-duc")

        if no_interactsh:
            command.append("-ni")

        tags = options.get("tags")
        if tags:
            command.extend(["-tags", tags])

        # allow specifying explicit template(s) to run via options['templates']
        templates = options.get("templates")
        if templates:
            if isinstance(templates, (list, tuple, set)):
                for t in templates:
                    if str(t).strip():
                        command.extend(["-t", str(t).strip()])
            else:
                command.extend(["-t", str(templates).strip()])

        severity = options.get("severity")
        if severity:
            command.extend(["-severity", severity])

        protocols = options.get("protocols")
        if protocols:
            if isinstance(protocols, (list, tuple, set)):
                protocol_value = ",".join(str(p).strip() for p in protocols if str(p).strip())
            else:
                protocol_value = str(protocols).strip()
            if protocol_value:
                command.extend(["-pt", protocol_value])

        exclude_tags = options.get("exclude_tags")
        if exclude_tags:
            if isinstance(exclude_tags, (list, tuple, set)):
                exclude_value = ",".join(str(t).strip() for t in exclude_tags if str(t).strip())
            else:
                exclude_value = str(exclude_tags).strip()
            if exclude_value:
                command.extend(["-etags", exclude_value])

        if bool(options.get("automatic_scan", False)):
            command.append("-as")

        return command

    def _needs_reduced_limits_retry(self, raw_output: str, returncode: int, retry_opaque_exit: bool = True) -> bool:
        normalized = (raw_output or "").lower()
        retry_markers = [
            "thread exhaustion",
            "exceeds 10000-thread limit",
            "panic: runtime error",
            "nil pointer dereference",
            "runtime: failed to create new os thread",
            "fatal error: newosproc",
            "too many open files",
        ]
        if any(marker in normalized for marker in retry_markers):
            return True

        # Some Windows failures return only a non-zero code with no stderr/stdout.
        return bool(retry_opaque_exit and returncode != 0 and not normalized.strip())

    def _needs_hard_stability_retry(self, raw_output: str, returncode: int) -> bool:
        if returncode == 0:
            return False

        normalized = (raw_output or "").lower()
        if not normalized.strip():
            return True

        hard_markers = [
            "fatal error:",
            "runtime/cgocall.go",
            "created by github.com/projectdiscovery/nuclei",
            "goroutine ",
            "runtime: failed to create new os thread",
            "too many open files",
        ]
        return any(marker in normalized for marker in hard_markers)
    
    def parse_json_output(self, json_file: Path) -> List[Finding]:
        """Parse Nuclei JSON output.

        Supports both JSONL and JSON array/object exports.
        """
        findings = []
        
        try:
            raw_text = json_file.read_text(encoding='utf-8', errors='replace').strip()
            if not raw_text:
                return findings

            records: List[Any] = []
            malformed_lines = 0

            if raw_text.startswith("["):
                try:
                    parsed = json.loads(raw_text)
                    if isinstance(parsed, list):
                        records = parsed
                    elif isinstance(parsed, dict):
                        records = [parsed]
                except json.JSONDecodeError:
                    # Salvage line-based records from partially-written JSON arrays.
                    for line in raw_text.splitlines():
                        candidate = line.strip().rstrip(",")
                        if not candidate or candidate in {"[", "]"}:
                            continue
                        try:
                            records.append(json.loads(candidate))
                        except json.JSONDecodeError:
                            malformed_lines += 1
            elif raw_text.startswith("{") and "\n" not in raw_text.strip():
                records = [json.loads(raw_text)]
            else:
                for line in raw_text.splitlines():
                    candidate = line.strip()
                    if not candidate:
                        continue
                    try:
                        records.append(json.loads(candidate))
                    except json.JSONDecodeError:
                        malformed_lines += 1

            if malformed_lines:
                self.logger.warning(
                    "Nuclei JSON output contained {} malformed line(s); parsed {} valid record(s)",
                    malformed_lines,
                    len(records),
                )

            for data in records:
                if not isinstance(data, dict):
                    continue

                info = data.get("info", {})
                if not isinstance(info, dict):
                    info = {}

                raw_severity = str(info.get("severity", "info")).lower()
                risk_mapping = {
                    "info": RiskLevel.INFO,
                    "low": RiskLevel.LOW,
                    "medium": RiskLevel.MEDIUM,
                    "high": RiskLevel.HIGH,
                    "critical": RiskLevel.CRITICAL
                }
                risk_level = risk_mapping.get(raw_severity, RiskLevel.INFO)

                classification = info.get("classification", {})
                if not isinstance(classification, dict):
                    classification = {}

                finding = Finding(
                    title=info.get("name", "Nuclei Finding"),
                    description=info.get("description", "-"),
                    risk_level=risk_level,
                    affected_url=data.get("matched-at", data.get("host", "")),
                    evidence={
                        "template": data.get("template-id"),
                        "matcher-name": data.get("matcher-name"),
                        "extracted-results": data.get("extracted-results", []),
                        "curl-command": data.get("curl-command")
                    },
                    recommendation=info.get("remediation", ""),
                    verified=True,
                    cvss_score=classification.get("cvss-score")
                )
                findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse nuclei JSON: {e}")
            
        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        return []
