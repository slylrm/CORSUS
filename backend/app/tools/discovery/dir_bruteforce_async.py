"""
Async directory brute force wrapper (no external binaries).
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.tools.base import BaseToolWrapper, RiskLevel, ToolResult
from app.utils.logger import logger


class DirBruteAsyncWrapper(BaseToolWrapper):
    name = "dir_brute"
    category = "discovery"
    description = "Async directory/endpoint brute force"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logger.bind(tool=self.name)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        return []

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = datetime.now()
        timeout = int(opts.get("timeout", 20))
        concurrency = int(opts.get("concurrency", 8))

        wordlist = opts.get("wordlist") or self.config.get("wordlist")
        if not wordlist:
            wordlist = [
                "admin",
                "login",
                "uploads",
                "backup",
                "config",
                "phpmyadmin",
                "server-status",
                "api",
                ".git/HEAD",
                "robots.txt",
                "sitemap.xml",
                "wp-admin",
                "dashboard",
                "portal",
                "console",
                "private",
            ]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {"tested": 0}

        sem = asyncio.Semaphore(concurrency)

        async def probe(path: str):
            url = urljoin(base + "/", path)
            try:
                async with sem:
                    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                        resp = await client.get(url)
                        metadata["tested"] += 1
                        if resp.status_code in (200, 301, 302, 401, 403):
                            findings.append({
                                "title": f"Interesting path discovered: {path}",
                                "description": f"Path {path} returned status {resp.status_code}",
                                "risk_level": RiskLevel.MEDIUM if resp.status_code in (200, 401, 403) else RiskLevel.INFO,
                                "affected_url": url,
                                "evidence": {"status_code": resp.status_code, "content_length": len(resp.text)},
                                "recommendation": "Review this endpoint for sensitive data or auth bypass",
                                "confidence_score": 0.72,
                            })
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        tasks = [asyncio.create_task(probe(path)) for path in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration = (datetime.now() - start_ts).total_seconds()

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            timestamp=start_ts,
            duration=duration,
            success=True,
            findings=findings,
            raw_output=f"tested={metadata['tested']}",
            errors=errors,
            metadata=metadata,
        )
