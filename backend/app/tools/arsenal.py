"""Optional security-tool inventory and safe process execution helpers.

The inventory is deliberately metadata-only: optional tools are never required
for the core application to start, and execution remains explicit per request.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ArsenalTool:
    name: str
    category: str
    version: str
    executable: str | None
    supported_os: tuple[str, ...]
    args: tuple[str, ...]
    defaults: tuple[str, ...]
    output: tuple[str, ...]
    timeout: int
    docs: str
    github: str
    docker: str | None = None
    optional: bool = True


_rows = [
    # name, category, version/current status, executable, args, defaults, output, timeout, docs, github, docker
    ("testssl", "tls", "3.2.5 (stable)", "testssl", ("--jsonfile", "--severity", "--fast"), ("--fast",), ("json", "csv", "html"), 300, "https://testssl.sh/", "https://github.com/testssl/testssl.sh", "drwetter/testssl.sh"),
    ("sslyze", "tls", "6.3.1", "sslyze", ("--json_out", "--regular", "--mozilla_config"), ("--regular",), ("json", "text"), 300, "https://nabla-c0d3.github.io/sslyze/", "https://github.com/nabla-c0d3/sslyze", None),
    ("sslscan", "tls", "2.2.4", "sslscan", ("--show-certificate", "--no-colour", "--xml", "--json"), ("--no-colour",), ("json", "xml", "text"), 180, "https://github.com/rbsec/sslscan", "https://github.com/rbsec/sslscan", "rbsec/sslscan"),
    ("nuclei", "web", "3.11.1", "nuclei", ("-jsonl", "-severity", "-rl", "-timeout", "-retries"), ("-jsonl", "-severity", "low,medium,high,critical", "-rl", "5", "-timeout", "10", "-retries", "1"), ("jsonl", "text"), 600, "https://docs.projectdiscovery.io/tools/nuclei/overview", "https://github.com/projectdiscovery/nuclei", "projectdiscovery/nuclei"),
    ("owasp_zap", "web", "2.17.0", None, ("-cmd", "-daemon", "-host", "-port"), (), ("json API", "xml", "html", "markdown"), 900, "https://www.zaproxy.org/docs/", "https://github.com/zaproxy/zaproxy", "ghcr.io/zaproxy/zaproxy:stable"),
    ("sqlmap", "web", "1.10.11", "sqlmap", ("--batch", "--risk", "--level", "--output-dir", "--forms"), ("--batch", "--risk=1", "--level=1"), ("json", "csv", "sqlite", "text"), 300, "https://github.com/sqlmapproject/sqlmap/wiki", "https://github.com/sqlmapproject/sqlmap", "paoloo/sqlmap"),
    ("ffuf", "web", "2.3.0", "ffuf", ("-u", "-w", "-of", "-o", "-rate", "-maxtime"), ("-of", "json", "-rate", "5"), ("json", "ejson", "csv", "html", "md"), 300, "https://github.com/ffuf/ffuf", "https://github.com/ffuf/ffuf", " ffuf/ffuf".strip()),
    ("httpx_pd", "web", "1.12.0", "httpx", ("-json", "-status-code", "-title", "-tech-detect", "-rate-limit"), ("-json", "-status-code", "-title", "-rate-limit", "5"), ("jsonl", "text"), 180, "https://docs.projectdiscovery.io/tools/httpx/overview", "https://github.com/projectdiscovery/httpx", "projectdiscovery/httpx"),
    ("nikto", "web", "2.6.1", "nikto", ("-host", "-output", "-Format", "-timeout"), ("-Format", "json"), ("json", "xml", "csv", "html", "text"), 600, "https://github.com/sullo/nikto/wiki", "https://github.com/sullo/nikto", None),
    ("wapiti", "web", "3.3.2", "wapiti", ("-u", "-f", "-o", "--max-scan-time", "--scope"), ("--scope", "url"), ("json", "html", "xml", "txt"), 600, "https://wapiti-scanner.github.io/", "https://github.com/wapiti-scanner/wapiti", "cyberwatch/wapiti"),
    ("dalfox", "web", "3.3.0", "dalfox", ("url", "--format", "--output", "--silence", "--deep-domxss"), ("url", "--format", "json"), ("json", "text"), 300, "https://dalfox.hahwul.com/", "https://github.com/hahwul/dalfox", "hahwul/dalfox"),
    ("nmap", "network", "7.993", "nmap", ("-sV", "-T2", "-p", "-oX", "--top-ports"), ("-T2", "--top-ports", "100"), ("xml", "gnmap", "text"), 600, "https://nmap.org/book/man.html", "https://github.com/nmap/nmap", "instrumentisto/nmap"),
    ("amass", "recon", "rolling (see releases)", "amass", ("enum", "-d", "-passive", "-json"), ("enum", "-passive"), ("json", "text"), 600, "https://owasp.org/www-project-amass/", "https://github.com/owasp-amass/amass", "caffix/amass"),
    ("semgrep", "sast", "rolling (see releases)", "semgrep", ("scan", "--config", "--json", "--timeout"), ("scan", "--json"), ("json", "text"), 300, "https://semgrep.dev/docs/", "https://github.com/semgrep/semgrep", None),
    ("gitleaks", "secrets", "rolling (see releases)", "gitleaks", ("detect", "git", "--report-format", "--report-path"), ("git", "--report-format", "json"), ("json", "sarif", "csv"), 300, "https://github.com/gitleaks/gitleaks", "https://github.com/gitleaks/gitleaks", "zricethezav/gitleaks"),
    ("trivy", "supply-chain", "rolling (see releases)", "trivy", ("fs", "image", "--format", "--scanners"), ("fs", "--format", "json"), ("json", "sarif", "table"), 600, "https://trivy.dev/latest/", "https://github.com/aquasecurity/trivy", "aquasec/trivy"),
    ("garak", "llm", "rolling (see releases)", "garak", ("--model_type", "--model_name", "--probes", "--report_prefix"), (), ("jsonl", "html", "text"), 900, "https://garak.ai/", "https://github.com/NVIDIA/garak", None),
    ("pyrit", "llm", "rolling (see releases)", "pyrit", ("--help",), (), ("console", "database"), 900, "https://azure.github.io/PyRIT/", "https://github.com/microsoft/PyRIT", None),
    ("promptfoo", "llm", "rolling (see releases)", "promptfoo", ("eval", "redteam", "--output", "--format"), (), ("json", "html", "csv"), 900, "https://www.promptfoo.dev/docs/", "https://github.com/promptfoo/promptfoo", None),
    ("playwright", "browser", "1.64.1 docs image", "playwright", ("install", "chromium"), (), ("json", "trace", "video"), 300, "https://playwright.dev/docs/intro", "https://github.com/microsoft/playwright", "mcr.microsoft.com/playwright"),
    ("chrome_headless", "browser", "installed Chrome version", "chrome", ("--headless", "--remote-debugging-port", "--user-data-dir"), ("--headless", "--disable-gpu"), ("devtools json", "screenshot"), 120, "https://developer.chrome.com/docs/chromium/headless", "https://github.com/GoogleChrome/chrome-launcher", None),
    ("cdp", "browser", "Chrome-versioned protocol", None, ("/json/version", "--remote-debugging-port"), (), ("JSON protocol messages",), 120, "https://chromedevtools.github.io/devtools-protocol/", "https://github.com/ChromeDevTools/devtools-protocol", None),
    ("chrome", "browser", "installed browser", "chrome", ("--headless", "--remote-debugging-port", "--user-data-dir"), ("--headless", "--disable-gpu"), ("devtools json", "screenshot"), 120, "https://developer.chrome.com/docs/chromium/headless", "https://chromedevtools.github.io/devtools-protocol/", None),
]

TOOLS: dict[str, ArsenalTool] = {
    row[0]: ArsenalTool(row[0], row[1], row[2], row[3], ("Windows", "Linux", "macOS"), tuple(row[4]), tuple(row[5]), tuple(row[6]), row[7], row[8], row[9], row[10] or None)
    for row in _rows
}


def inventory() -> list[dict[str, Any]]:
    """Return manager metadata and local availability, without launching tools."""
    browser_candidates = [
        shutil.which(name) for name in ("chrome", "chrome.exe", "google-chrome", "msedge")
    ]
    browser_candidates.extend(
        str(Path(root) / suffix)
        for root in (os.environ.get("PROGRAMFILES", ""), os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("LOCALAPPDATA", ""))
        if root
        for suffix in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe")
    )
    browser_path = next((candidate for candidate in browser_candidates if candidate and Path(candidate).is_file()), None)
    result = []
    for tool in TOOLS.values():
        executable = shutil.which(tool.executable) if tool.executable else None
        if tool.name in {"chrome", "chrome_headless", "cdp"}:
            executable = executable or browser_path
        result.append({
            "name": tool.name, "category": tool.category, "version": tool.version,
            "installed": bool(executable) or tool.name == "owasp_zap",
            "executable_path": executable, "supported_os": list(tool.supported_os),
            "cli_arguments": list(tool.args), "default_arguments": list(tool.defaults),
            "output_formats": list(tool.output), "timeout_seconds": tool.timeout,
            "docker_image": tool.docker, "documentation_url": tool.docs,
            "github_url": tool.github, "optional": tool.optional,
        })
    return result


async def run_tool(name: str, target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a narrowly scoped safe probe; arguments are constructed as argv, never shell text."""
    tool = TOOLS.get(name)
    if not tool or tool.category in {"llm", "browser"} or name == "owasp_zap":
        raise ValueError("Tool is inventory-only or is not executable through this endpoint")
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or not (host == "localhost" or host.endswith(".localhost") or host in {"127.0.0.1", "::1"}):
        raise ValueError("Execution is limited to localhost targets; remote targets require an explicit scoped integration")
    exe = shutil.which(tool.executable or "")
    if not exe:
        raise FileNotFoundError(f"{name} is not installed")
    options = options or {}
    allowed = {"timeout": int}
    if set(options) - set(allowed):
        raise ValueError("Unsupported execution options")
    timeout = max(1, min(int(options.get("timeout", tool.timeout)), 900))
    argv = [exe]
    output_path: str | None = None
    if name in {"testssl", "sslyze", "sslscan"}:
        handle = tempfile.NamedTemporaryFile(prefix="weppentest_tls_", suffix=".json", delete=False)
        output_path = handle.name
        handle.close()
    if name == "nuclei": argv += ["-u", target, "-ni", *tool.defaults]
    elif name == "nmap": argv += ["-T2", "--top-ports", "100", "-oX", "-", host]
    elif name == "sqlmap": argv += ["-u", target, "--batch", "--risk=1", "--level=1", "--smart"]
    elif name == "httpx_pd": argv += ["-u", target, "-json", "-status-code", "-title", "-rate-limit", "5"]
    elif name == "nikto": argv += ["-host", target, "-Format", "json"]
    elif name == "wapiti": argv += ["-u", target, "-f", "json", "--scope", "url"]
    elif name == "ffuf": raise ValueError("ffuf requires a user-supplied wordlist and is not enabled by generic execution")
    elif name == "dalfox": argv += ["url", target, "--format", "json", "--silence"]
    elif name == "sslyze": argv += [f"--json_out={output_path}", host]
    elif name == "sslscan": argv += ["--no-colour", f"--json={output_path}", host]
    elif name == "testssl": argv += ["--jsonfile", output_path, "--fast", host]
    else: raise ValueError("No safe execution profile is defined")
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except Exception:
        if output_path:
            try: Path(output_path).unlink(missing_ok=True)
            except OSError: pass
        raise
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        raw = (stdout or stderr).decode("utf-8", errors="replace")
        if output_path:
            try:
                raw = Path(output_path).read_text(encoding="utf-8", errors="replace") or raw
            except OSError:
                pass
        parsed_output: Any = None
        try:
            parsed_output = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            records = []
            for line in raw.splitlines():
                try: records.append(json.loads(line))
                except json.JSONDecodeError: continue
            if records: parsed_output = records
        return {"tool": name, "target": target, "exit_code": process.returncode, "status": "completed" if process.returncode == 0 else "error", "output": parsed_output if parsed_output is not None else raw[-20000:]}
    except asyncio.TimeoutError:
        process.kill()
        stdout, _ = await process.communicate()
        return {"tool": name, "target": target, "status": "timeout", "timeout_seconds": timeout, "output": stdout.decode("utf-8", errors="replace")[-20000:]}
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise
    finally:
        if output_path:
            try: Path(output_path).unlink(missing_ok=True)
            except OSError: pass
