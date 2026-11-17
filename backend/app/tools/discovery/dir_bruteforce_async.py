"""
Async directory brute force wrapper (no external binaries).
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.tools.base import BaseToolWrapper, RiskLevel, ToolResult
from app.config import settings
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
        timeout = float(opts.get("timeout", 6))
        concurrency = int(opts.get("concurrency", 20))
        # Early stop heuristic: stop after N consecutive 404s to avoid wasting time
        stop_on_404_streak = int(opts.get("stop_on_404_streak", 20))

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
        max_paths = int(opts.get("max_paths", len(wordlist)))
        wordlist = list(wordlist)[:max_paths]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {"tested": 0, "concurrency": concurrency, "timeout": timeout, "max_paths": len(wordlist)}

        sem = asyncio.Semaphore(concurrency)
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        client_timeout = httpx.Timeout(timeout, connect=min(timeout, 3.0))

        stop_event = asyncio.Event()
        counters_lock = asyncio.Lock()
        counters = {"consecutive_404": 0}

        async def probe(client: httpx.AsyncClient, path: str):
            url = urljoin(base + "/", path)
            # Respect early-stop signal
            if stop_event.is_set():
                return
            try:
                async with sem:
                    # First try a HEAD to avoid fetching large responses
                    try:
                        resp = await client.head(url)
                    except Exception:
                        # Some servers don't handle HEAD properly — fallback to GET
                        resp = await client.get(url)

                    async with counters_lock:
                        metadata["tested"] += 1

                    status = resp.status_code

                    if status in (200, 301, 302, 401, 403):
                        # For 200 fetch body to get content length; for others record status only
                        content_length = 0
                        if status == 200:
                            try:
                                # GET to obtain body
                                full = await client.get(url)
                                content_length = len(full.text)
                            except Exception:
                                content_length = 0

                        findings.append({
                            "title": f"Interesting path discovered: {path}",
                            "description": f"Path {path} returned status {status}",
                            "risk_level": RiskLevel.MEDIUM if status in (200, 401, 403) else RiskLevel.INFO,
                            "affected_url": url,
                            "evidence": {"status_code": status, "content_length": content_length},
                            "recommendation": "Review this endpoint for sensitive data or auth bypass",
                            "confidence_score": 0.72,
                        })
                        # reset 404 counter on any non-404
                        async with counters_lock:
                            counters["consecutive_404"] = 0
                    else:
                        # treat 404 as negative; increase counter and possibly trigger stop
                        async with counters_lock:
                            if status == 404:
                                counters["consecutive_404"] += 1
                                if counters["consecutive_404"] >= stop_on_404_streak:
                                    stop_event.set()
                            else:
                                counters["consecutive_404"] = 0

            except Exception as exc:  # noqa: BLE001
                message = str(exc).strip() or exc.__class__.__name__
                if message not in errors:
                    errors.append(message)

        async with httpx.AsyncClient(
            timeout=client_timeout,
            follow_redirects=True,
            limits=limits,
            verify=settings.HTTP_VERIFY_TLS,
        ) as client:
            tasks = [asyncio.create_task(probe(client, path)) for path in wordlist]
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
