"""
Gitleaks Wrapper - Secrets Scanner
"""

import shutil
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.tools.base import (
    BaseToolWrapper,
    Finding,
    RiskLevel,
    ToolCategory,
    ToolResult,
)
from app.config import settings


class GitleaksWrapper(BaseToolWrapper):
    """
    Gitleaks secrets scanner wrapper.
    Accepts a URL or a local directory path as target.
    When given a URL, tries to git-clone the repository first.
    """

    name = "gitleaks"
    category = ToolCategory.CUSTOM
    description = "Static application security testing tool for detecting hardcoded secrets"
    version = "8.18"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.gitleaks_path = (
            config.get("path", getattr(settings, "GITLEAKS_PATH", "gitleaks"))
            if config
            else getattr(settings, "GITLEAKS_PATH", "gitleaks")
        )

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        start_time = datetime.now()
        options = options or {}

        tmpdir: Optional[str] = None
        scan_source: str = target
        use_no_git = options.get("no_git", False)
        extra_findings: List[Finding] = []

        # URL hedefse önce git clone dene
        if target.startswith(("http://", "https://")):
            temp_root = Path(__file__).resolve().parents[4] / ".tmp" / "gitleaks-clones"
            temp_root.mkdir(parents=True, exist_ok=True)
            tmpdir = str(temp_root / f"gitleaks_clone_{uuid.uuid4().hex}")
            try:
                if Path(tmpdir).exists():
                    shutil.rmtree(tmpdir, ignore_errors=True)
                clone_result = subprocess.run(
                    ["git", "clone", "--depth=1", "--quiet", target, tmpdir],
                    capture_output=True,
                    timeout=120,
                )
                if clone_result.returncode == 0:
                    self.logger.info(f"[GITLEAKS] Cloned {target} into {tmpdir}")
                    scan_source = tmpdir
                    use_no_git = False
                else:
                    self.logger.warning(
                        f"[GITLEAKS] Could not clone {target}: {clone_result.stderr.decode(errors='replace').strip()}"
                    )
                    # Clone başarısız – exposed .git kontrol et
                    exposed = self._check_exposed_git(target)
                    if exposed:
                        extra_findings.append(
                            Finding(
                                title="Exposed .git Directory",
                                description=(
                                    f"The .git directory appears to be publicly accessible at {target}/.git/. "
                                    "An attacker can reconstruct the source code and find hardcoded secrets."
                                ),
                                risk_level=RiskLevel.CRITICAL,
                                affected_url=f"{target.rstrip('/')}/.git/",
                                evidence={"url": f"{target.rstrip('/')}/.git/config"},
                                recommendation=(
                                    "Block access to the .git directory in your web server configuration "
                                    "(e.g. deny all for /.git in nginx/Apache)."
                                ),
                                verified=True,
                            )
                        )
                    # Klonlama olmadan taramamıza gerek yok
                    duration = (datetime.now() - start_time).total_seconds()
                    return ToolResult(
                        tool_name=self.name,
                        category=self.category.value,
                        target=target,
                        timestamp=start_time,
                        duration=duration,
                        success=True,
                        findings=[f.to_dict() for f in extra_findings],
                        raw_output="git clone failed; no local source to scan",
                        errors=[],
                        metadata={"note": "git clone failed", "exposed_git": exposed},
                    )
            except subprocess.TimeoutExpired:
                self.logger.warning(f"[GITLEAKS] git clone timed out for {target}")
                duration = (datetime.now() - start_time).total_seconds()
                return ToolResult(
                    tool_name=self.name,
                    category=self.category.value,
                    target=target,
                    timestamp=start_time,
                    duration=duration,
                    success=False,
                    findings=[],
                    raw_output="git clone timed out",
                    errors=["git clone timed out"],
                    metadata={},
                )
            except FileNotFoundError:
                self.logger.warning("[GITLEAKS] git not found in PATH, skipping clone")
                duration = (datetime.now() - start_time).total_seconds()
                return ToolResult(
                    tool_name=self.name,
                    category=self.category.value,
                    target=target,
                    timestamp=start_time,
                    duration=duration,
                    success=False,
                    findings=[],
                    raw_output="git executable not found",
                    errors=["git not found in PATH"],
                    metadata={},
                )

        json_output = settings.GITLEAKS_OUTPUT_DIR / f"gitleaks_{datetime.now().timestamp()}.json"
        json_output.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.gitleaks_path,
            "detect",
            "--report-format", "json",
            "--report-path", str(json_output),
            "--source", scan_source,
        ]
        if use_no_git:
            command.append("--no-git")

        findings: List[Finding] = list(extra_findings)
        errors = []
        raw_output = ""
        success = False

        try:
            result = self._execute_command(command, timeout=300)
            raw_output = result.stdout + result.stderr

            if json_output.exists():
                findings.extend(self.parse_json_output(json_output))

            # exit 0 = no leaks, exit 1 = leaks found (still success), other = error
            success = result.returncode in [0, 1]

        except Exception as e:
            self.logger.error(f"Gitleaks execution failed: {e}")
            errors.append(str(e))
            success = False
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

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
            metadata={"command": " ".join(command)},
        )

    def _check_exposed_git(self, target_url: str) -> bool:
        """Returns True if /.git/config is publicly accessible at target_url."""
        try:
            import requests
            url = target_url.rstrip("/") + "/.git/config"
            resp = requests.get(url, timeout=5, verify=settings.HTTP_VERIFY_TLS, allow_redirects=False)
            if resp.status_code == 200 and "[core]" in resp.text:
                return True
        except Exception:
            pass
        return False

    def parse_json_output(self, json_file: Path) -> List[Finding]:
        """Parse Gitleaks JSON output"""
        import json
        findings = []
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for leak in data:
                finding = Finding(
                    title=f"Hardcoded Secret: {leak.get('Description')}",
                    description=f"A {leak.get('RuleID')} secret was found in the repository.",
                    risk_level=RiskLevel.CRITICAL,
                    affected_url=f"file://{leak.get('File')}#L{leak.get('StartLine')}",
                    evidence={
                        "rule": leak.get("RuleID"),
                        "match": leak.get("Match"),
                        "secret": "***" + leak.get("Secret", "")[-4:] if leak.get("Secret") else "***",
                        "file": leak.get("File"),
                        "line": leak.get("StartLine"),
                        "commit": leak.get("Commit"),
                    },
                    recommendation=(
                        "Revoke the exposed secret immediately, rotate it, and remove the "
                        "hardcoded reference from the source code repository."
                    ),
                    verified=True,
                )
                findings.append(finding)
        except Exception as e:
            self.logger.error(f"Failed to parse gitleaks JSON: {e}")
        return findings

    def parse_output(self, raw_output: str) -> List[Finding]:
        return []
