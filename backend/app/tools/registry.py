"""
Central pentest tool registry.

Provides:
- runtime installation detection
- scan-target resolution per tool type
- default tool sets aligned with the project documentation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse
import shutil
import requests

from app.config import settings
from app.tools.discovery.amass_wrapper import AmassWrapper
from app.tools.discovery.nikto_wrapper import NiktoWrapper
from app.tools.discovery.nmap_wrapper import NmapWrapper
from app.tools.discovery.nuclei_wrapper import NucleiWrapper
from app.tools.discovery.zap_scanner_wrapper import ZapScannerWrapper
from app.tools.injection.sqlmap_wrapper import SQLMapWrapper
from app.tools.injection.wapiti_wrapper import WapitiWrapper
from app.tools.sast.semgrep_wrapper import SemgrepWrapper
from app.tools.container.trivy_wrapper import TrivyWrapper
from app.tools.secrets.gitleaks_wrapper import GitleaksWrapper


PROJECT_ROOT = Path(__file__).resolve().parents[3]
APP_BIN_DIR = PROJECT_ROOT / "backend" / "app" / "bin"
VENV_SCRIPTS_DIR = PROJECT_ROOT / ".venv" / "Scripts"
EXTERNAL_TOOL_ROOTS: tuple[Path, ...] = (
    PROJECT_ROOT / "niktowap",
    PROJECT_ROOT.parent / "niktowap",
    PROJECT_ROOT / "nikto wap",
    PROJECT_ROOT.parent / "nikto wap",
)


def _external_tool_candidates(tool_name: str) -> list[Path]:
    candidates: list[Path] = []
    for root in EXTERNAL_TOOL_ROOTS:
        if tool_name == "nikto":
            candidates.extend(
                [
                    root / "nikto-main",
                    root / "nikto-main" / "program" / "nikto.pl",
                    root / "nikto-main" / "nikto.pl",
                ]
            )
        elif tool_name == "wapiti":
            candidates.extend(
                [
                    root / "wapiti-master",
                    root / "wapiti-master" / "bin" / "wapiti",
                    root / "wapiti-master" / "bin" / "wapiti.py",
                ]
            )
    return candidates


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    category: str
    description: str
    version: str
    wrapper: Any | None = None
    path_setting: Optional[str] = None
    requires_sudo: bool = False
    aliases: tuple[str, ...] = ()
    target_kind: str = "url"
    service_url_setting: Optional[str] = None
    capabilities: tuple[str, ...] = ()
    option_schema: Dict[str, Any] = field(default_factory=dict)


TOOL_DEFINITIONS: Dict[str, ToolDefinition] = {
    "amass": ToolDefinition(
        name="amass",
        category="discovery",
        description="In-depth asset discovery and attack-surface mapping",
        version="4.2",
        wrapper=AmassWrapper,
        path_setting="AMASS_PATH",
        target_kind="host",
        capabilities=("subdomain enumeration", "asset discovery", "attack-surface mapping"),
    ),
    "nmap": ToolDefinition(
        name="nmap",
        category="discovery",
        description="Network mapper, port scanner, and service fingerprinting",
        version="7.993",
        wrapper=NmapWrapper,
        path_setting="NMAP_PATH",
        target_kind="host",
        capabilities=("port scanning", "service detection", "NSE-based checks"),
    ),
    "owasp_zap": ToolDefinition(
        name="owasp_zap",
        category="dast",
        description="OWASP ZAP dynamic web application security scanner",
        version="2.17.0",
        wrapper=ZapScannerWrapper,
        target_kind="url",
        service_url_setting="ZAP_API_URL",
        aliases=("zap", "zap_scanner"),
        capabilities=("proxy scanning", "spidering", "passive scan", "active scan"),
        option_schema={
            "active_scan": {"type": "bool", "default": False},
            "zap_host": {"type": "string", "default": settings.ZAP_API_URL},
        },
    ),
    "nuclei": ToolDefinition(
        name="nuclei",
        category="vulnerability_scanner",
        description="Template-based fast vulnerability scanner",
        version="3.11.1",
        wrapper=NucleiWrapper,
        path_setting="NUCLEI_PATH",
        target_kind="url",
        capabilities=("CVE detection", "misconfiguration checks", "secret exposure detection"),
    ),
    "nikto": ToolDefinition(
        name="nikto",
        category="misconfiguration",
        description="Web server misconfiguration and dangerous-file scanner",
        version="2.6.1",
        wrapper=NiktoWrapper,
        path_setting="NIKTO_PATH",
        target_kind="url",
        capabilities=("server hardening checks", "dangerous files", "known bad defaults"),
    ),
    "wapiti": ToolDefinition(
        name="wapiti",
        category="dast",
        description="Black-box web application vulnerability fuzzer",
        version="3.3.2",
        wrapper=WapitiWrapper,
        path_setting="WAPITI_PATH",
        target_kind="url",
        capabilities=("parameter fuzzing", "black-box DAST", "crawler-based testing"),
    ),
    "sqlmap": ToolDefinition(
        name="sqlmap",
        category="injection",
        description="Automated SQL injection detection and validation",
        version="1.10.11",
        wrapper=SQLMapWrapper,
        path_setting="SQLMAP_PATH",
        target_kind="url",
        capabilities=("SQLi detection", "DB fingerprinting", "payload automation"),
        option_schema={
            "level": {"type": "int", "default": 1},
            "risk": {"type": "int", "default": 1},
            "threads": {"type": "int", "default": 1},
        },
    ),
    "semgrep": ToolDefinition(
        name="semgrep",
        category="sast",
        description="Static code analysis for application security issues",
        version="1.159",
        wrapper=SemgrepWrapper,
        path_setting="SEMGREP_PATH",
        target_kind="repo",
        capabilities=("SAST", "framework-aware rules", "code-level findings"),
    ),
    "gitleaks": ToolDefinition(
        name="gitleaks",
        category="secrets",
        description="Hardcoded secret and credential scanner",
        version="8.23",
        wrapper=GitleaksWrapper,
        path_setting="GITLEAKS_PATH",
        target_kind="url",
        capabilities=("secret detection", "git history scan", "credential leak detection"),
    ),
    "trivy": ToolDefinition(
        name="trivy",
        category="container_security",
        description="Filesystem, image, and supply-chain scanner",
        version="0.49",
        wrapper=TrivyWrapper,
        path_setting="TRIVY_PATH",
        target_kind="repo",
        capabilities=("filesystem scan", "dependency vulnerabilities", "supply-chain review"),
        option_schema={
            "scan_type": {"type": "string", "default": "fs"},
        },
    ),
    "metasploit": ToolDefinition(
        name="metasploit",
        category="exploitation",
        description="Metasploit RPC integration endpoint",
        version="6.x",
        service_url_setting="METASPLOIT_RPC_URL",
        capabilities=("RPC automation", "PoC validation", "payload orchestration"),
    ),
    "defectdojo": ToolDefinition(
        name="defectdojo",
        category="vulnerability_management",
        description="DefectDojo platform integration endpoint",
        version="2.x",
        service_url_setting="DEFECTDOJO_URL",
        capabilities=("finding ingestion", "deduplication", "tracking"),
    ),
    "faraday": ToolDefinition(
        name="faraday",
        category="collaboration",
        description="Faraday collaboration platform integration endpoint",
        version="4.x",
        service_url_setting="FARADAY_URL",
        capabilities=("team collaboration", "centralized findings", "workspace sync"),
    ),
}


ALIAS_TO_TOOL = {
    alias: definition.name
    for definition in TOOL_DEFINITIONS.values()
    for alias in (definition.name, *definition.aliases)
}


def canonical_tool_name(name: str) -> str:
    return ALIAS_TO_TOOL.get(name.strip().lower(), name.strip().lower())


def get_tool_definition(name: str) -> Optional[ToolDefinition]:
    return TOOL_DEFINITIONS.get(canonical_tool_name(name))


def iter_tool_definitions() -> Iterable[ToolDefinition]:
    return TOOL_DEFINITIONS.values()


def _candidate_paths(tool_name: str, configured_path: Optional[str]) -> list[Path]:
    exe_names = [tool_name, f"{tool_name}.exe"]
    candidates: list[Path] = []

    if configured_path:
        normalized = configured_path.strip().strip('"').strip("'")
        if normalized:
            configured_candidate = Path(normalized)
            candidates.append(configured_candidate)
            if tool_name == "nikto":
                candidates.extend(
                    [
                        configured_candidate / "program" / "nikto.pl",
                        configured_candidate / "nikto.pl",
                    ]
                )
            if tool_name == "wapiti":
                candidates.extend(
                    [
                        configured_candidate / "bin" / "wapiti",
                        configured_candidate / "bin" / "wapiti.py",
                        configured_candidate / "wapiti",
                        configured_candidate / "wapiti.py",
                    ]
                )

    for exe_name in exe_names:
        candidates.append(APP_BIN_DIR / exe_name)
        candidates.append(VENV_SCRIPTS_DIR / exe_name)

    if tool_name == "nikto":
        nikto_root = APP_BIN_DIR / "nikto"
        candidates.extend(
            [
                nikto_root,
                nikto_root / "program" / "nikto.pl",
                nikto_root / "nikto.pl",
            ]
        )
    if tool_name == "wapiti":
        wapiti_root = APP_BIN_DIR / "wapiti"
        candidates.extend(
            [
                wapiti_root,
                wapiti_root / "bin" / "wapiti",
                wapiti_root / "bin" / "wapiti.py",
                wapiti_root / "wapiti",
                wapiti_root / "wapiti.py",
            ]
        )

    candidates.extend(_external_tool_candidates(tool_name))

    which_path = shutil.which(tool_name)
    if which_path:
        candidates.append(Path(which_path))

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _resolve_candidate_path(tool_name: str, candidate: Path) -> Optional[Path]:
    if candidate.is_file():
        return candidate

    if tool_name == "nikto" and candidate.is_dir():
        for script_path in (
            candidate / "program" / "nikto.pl",
            candidate / "nikto.pl",
            candidate / "program" / "nikto",
        ):
            if script_path.is_file():
                return script_path

    if tool_name == "wapiti" and candidate.is_dir():
        for script_path in (
            candidate / "bin" / "wapiti",
            candidate / "bin" / "wapiti.py",
            candidate / "wapiti",
            candidate / "wapiti.py",
        ):
            if script_path.is_file():
                return script_path

    return None


def resolve_tool_path(name: str) -> Optional[str]:
    definition = get_tool_definition(name)
    if not definition or not definition.path_setting:
        return None

    configured_path = getattr(settings, definition.path_setting, None)
    for candidate in _candidate_paths(definition.name, configured_path):
        resolved_candidate = _resolve_candidate_path(definition.name, candidate)
        if resolved_candidate is not None:
            return str(resolved_candidate)
    return None


def is_tool_installed(name: str) -> bool:
    definition = get_tool_definition(name)
    if not definition:
        return False
    if definition.path_setting:
        if resolve_tool_path(name) is not None:
            return True
        # Nikto special case: git-stream fallback via NIKTO_GIT_SOURCE or bundled backup
        if definition.name == "nikto":
            git_source = getattr(settings, "NIKTO_GIT_SOURCE", None) or ""
            git_source = git_source.strip().strip('"').strip("'")
            candidates: list[Path] = []
            if git_source:
                candidates.append(Path(git_source))
            # also check bundled nikto_backup_* dirs
            for backup in sorted(APP_BIN_DIR.glob("nikto_backup_*"), reverse=True):
                candidates.append(backup)
            for cand in candidates:
                if cand.is_dir() and (cand / ".git").exists():
                    # verify nikto.pl is accessible via git
                    try:
                        import subprocess as _sp
                        result = _sp.run(
                            ["git", "show", "HEAD:program/nikto.pl"],
                            cwd=str(cand),
                            capture_output=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            return True
                    except Exception:
                        pass
        return False
    if definition.service_url_setting:
        service_url = getattr(settings, definition.service_url_setting, None)
        if not service_url:
            return False
        test_url = service_url.rstrip("/")
        if definition.name == "owasp_zap":
            test_url = f"{test_url}/JSON/core/view/version/"
        try:
            params = {"apikey": settings.ZAP_API_KEY} if definition.name == "owasp_zap" and settings.ZAP_API_KEY else None
            response = requests.get(test_url, params=params, timeout=2, verify=settings.HTTP_VERIFY_TLS)
            return response.ok
        except Exception:
            return False
    return False


def get_repository_scan_path() -> str:
    configured = settings.REPOSITORY_SCAN_PATH
    repo_path = configured if configured.is_absolute() else (PROJECT_ROOT / configured)
    return str(repo_path.resolve())


def resolve_scan_target(name: str, target_url: str) -> str:
    definition = get_tool_definition(name)
    if not definition:
        return target_url

    if definition.target_kind == "repo":
        return get_repository_scan_path()

    parsed = urlparse(target_url)
    hostname = parsed.hostname or parsed.netloc or target_url
    if definition.target_kind == "host":
        return hostname
    return target_url


def build_tool_options(name: str, scan_type: str) -> Dict[str, Any]:
    canonical = canonical_tool_name(name)
    if canonical == "dir_brute":
        if scan_type == "quick":
            return {"timeout": 4, "concurrency": 32, "max_paths": 12, "stop_on_404_streak": 6}
        if scan_type == "standard":
            return {"timeout": 5, "concurrency": 28, "max_paths": 16, "stop_on_404_streak": 10}
        return {"timeout": 6, "concurrency": 28, "max_paths": 32, "stop_on_404_streak": 20}
    if canonical == "crawler":
        if scan_type == "quick":
            return {"timeout": 5, "concurrency": 10, "max_depth": 1, "max_urls": 20}
        if scan_type == "standard":
            return {"timeout": 6, "concurrency": 12, "max_depth": 1, "max_urls": 30}
        return {"timeout": 8, "concurrency": 14, "max_depth": 2, "max_urls": 45}
    if canonical == "nmap":
        if scan_type == "quick":
            return {"scan_type": "fast", "ports": "80,443,8080,8443", "timeout": 90, "tool_timeout": 120}
        if scan_type == "standard":
            return {"scan_type": "fast", "ports": "1-1024,8080,8443", "timeout": 120, "tool_timeout": 150}
        return {"scan_type": "fast", "ports": "1-1024,3306,5432,6379,8080,8443", "timeout": 150, "tool_timeout": 180}
    if canonical == "amass":
        if scan_type == "quick":
            return {"active": False, "tool_timeout": 300}
        if scan_type == "standard":
            return {"active": False, "tool_timeout": 480}
        return {"active": False, "tool_timeout": 720}
    if canonical == "owasp_zap":
        return {"active_scan": False, "zap_host": settings.ZAP_API_URL, "api_key": settings.ZAP_API_KEY}
    if canonical == "wapiti":
        if scan_type == "quick":
            max_scan_time = 2
        elif scan_type == "standard":
            max_scan_time = 5
        else:
            max_scan_time = 10
        return {
            "deep_scan": scan_type == "deep",
            "max_scan_time": max_scan_time,
            # Wapiti uses minutes for --max-scan-time; keep outer timeout in seconds with margin.
            "tool_timeout": (max_scan_time * 60) + 180,
        }
    if canonical == "sqlmap":
        if scan_type == "deep":
            return {"level": 2, "risk": 2, "threads": 2, "tool_timeout": 180}
        return {"level": 1, "risk": 1, "threads": 1, "tool_timeout": 120}
    if canonical == "nikto":
        if scan_type == "quick":
            return {"timeout": 15, "tool_timeout": 180}
        if scan_type == "standard":
            return {"timeout": 20, "tool_timeout": 300}
        return {"timeout": 25, "tool_timeout": 420}
    if canonical == "nuclei":
        if scan_type == "quick":
            per_attempt_timeout = 90
            outer_timeout = 240
            retry_on_timeout = False
            request_timeout = 10
        elif scan_type == "standard":
            per_attempt_timeout = 120
            outer_timeout = 300
            retry_on_timeout = True
            request_timeout = 12
        else:
            per_attempt_timeout = 180
            outer_timeout = 480
            retry_on_timeout = True
            request_timeout = 15
        return {
            "severity": "info,low,medium,high,critical" if scan_type == "deep" else "high,medium",
            "timeout": per_attempt_timeout,
            "tool_timeout": outer_timeout,
            "retry_opaque_exit": True,
            "retry_on_timeout": retry_on_timeout,
            "hard_stability_retry": True,
            "concurrency": 4,
            "rate_limit": 15,
            "bulk_size": 4,
            "retries": 0,
            "disable_update_check": True,
            "no_interactsh": True,
            "request_timeout": request_timeout,
            "headless_concurrency": 2,
            "headless_bulk_size": 2,
            "payload_concurrency": 4,
            "hard_retry_tags": "cve,misconfig,exposure",
            "protocols": "http,ssl",
            "exclude_tags": "fuzz,dos,bruteforce",
            "automatic_scan": True,
        }
    if canonical == "fingerprint":
        if scan_type == "quick":
            return {"timeout": 8, "connect_timeout": 5, "connect_retries": 1}
        if scan_type == "standard":
            return {"timeout": 10, "connect_timeout": 6, "connect_retries": 1}
        return {"timeout": 12, "connect_timeout": 7, "connect_retries": 2}
    if canonical in {"basic", "headers"}:
        return {"timeout": 8}
    if canonical == "ssl":
        return {"timeout": 6}
    if canonical == "trivy":
        if scan_type == "quick":
            command_timeout = 180
        elif scan_type == "standard":
            command_timeout = 240
        else:
            command_timeout = 300
        return {
            "scan_type": "fs",
            "timeout": command_timeout,
            "tool_timeout": command_timeout + 120,
            "scanners": "vuln",
            "skip_version_check": True,
            "quiet": True,
        }
    return {}


def get_tool_plan(name: str, scan_type: str, target_url: str) -> Optional[Dict[str, Any]]:
    definition = get_tool_definition(name)
    if not definition or not definition.wrapper:
        return None

    config: Dict[str, Any] = {}
    resolved_path = resolve_tool_path(definition.name)
    if resolved_path:
        config["path"] = resolved_path
    if definition.name == "nikto":
        git_source = getattr(settings, "NIKTO_GIT_SOURCE", None) or ""
        git_source = git_source.strip().strip('"').strip("'")
        if not git_source:
            # Auto-detect bundled nikto_backup_* as git-stream source
            for backup in sorted(APP_BIN_DIR.glob("nikto_backup_*"), reverse=True):
                if (backup / ".git").exists():
                    git_source = str(backup)
                    break
        if git_source:
            config["nikto_git_source"] = git_source

    return {
        "tool_class": definition.wrapper,
        "config": config,
        "target": resolve_scan_target(definition.name, target_url),
        "options": build_tool_options(definition.name, scan_type),
    }


def get_default_tool_names(scan_type: str) -> list[str]:
    if scan_type == "quick":
        return ["crawler", "fingerprint", "headers", "ssl"]
    if scan_type == "standard":
        return [
            "crawler",
            "dir_brute",
            "fingerprint",
            "basic",
            "headers",
            "ssl",
            "ports",
            "nmap",
            "nuclei",
        ]
    return [
        "crawler",
        "dir_brute",
        "fingerprint",
        "basic",
        "headers",
        "ssl",
        "ports",
        "amass",
        "nmap",
        "nuclei",
        "nikto",
        "owasp_zap",
        "wapiti",
        "sqlmap",
        "semgrep",
        "gitleaks",
        "trivy",
    ]


def filter_installed_tool_names(tool_names: Iterable[str]) -> list[str]:
    filtered: list[str] = []
    for tool_name in tool_names:
        canonical = canonical_tool_name(tool_name)
        definition = get_tool_definition(canonical)
        if not definition or definition.wrapper is None:
            filtered.append(canonical)
            continue
        if is_tool_installed(canonical):
            filtered.append(canonical)
    return filtered
