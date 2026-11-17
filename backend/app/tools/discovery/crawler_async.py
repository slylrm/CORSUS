"""
Async Crawler Wrapper
Lightweight crawler with depth/host limits and async HTTP fetch.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.tools.base import BaseToolWrapper, RiskLevel, ToolResult
from app.config import settings
from app.utils.logger import logger


class AsyncCrawlerWrapper(BaseToolWrapper):
    name = "crawler"
    category = "discovery"
    description = "Async HTML crawler with depth and host limits"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Skip binary validation
        self.config = config or {}
        self.logger = logger.bind(tool=self.name)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        return []

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = datetime.now()
        max_depth = int(opts.get("max_depth", 1))
        concurrency = int(opts.get("concurrency", 12))
        timeout = float(opts.get("timeout", 8))
        max_urls = int(opts.get("max_urls", 40))

        parsed_root = urlparse(target)
        base_host = parsed_root.netloc

        visited: Set[str] = set()
        to_visit: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await to_visit.put((target, 0))

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {"visited": 0, "discovered": [], "max_urls": max_urls}

        client_timeout = httpx.Timeout(timeout, connect=min(timeout, 3.0))
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)

        async def fetch_url(client: httpx.AsyncClient, url: str, depth: int):
            if depth > max_depth or url in visited or len(visited) >= max_urls:
                return
            visited.add(url)
            metadata["visited"] += 1
            try:
                resp = await client.get(url)
                metadata["discovered"].append({"url": url, "status": resp.status_code})
                server = resp.headers.get("server")
                x_powered = resp.headers.get("x-powered-by")
                if server:
                    findings.append({
                        "title": "Server header exposed",
                        "description": f"Server header present on {url}",
                        "risk_level": RiskLevel.LOW,
                        "affected_url": url,
                        "evidence": {"server": server},
                        "recommendation": "Hide or minimize server banner",
                        "confidence_score": 0.7,
                    })
                if x_powered:
                    findings.append({
                        "title": "Technology stack disclosed",
                        "description": f"X-Powered-By header exposed on {url}",
                        "risk_level": RiskLevel.LOW,
                        "affected_url": url,
                        "evidence": {"x_powered_by": x_powered},
                        "recommendation": "Remove X-Powered-By header",
                        "confidence_score": 0.75,
                    })
                if depth >= max_depth:
                    return
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(["a", "link"], href=True):
                    href = tag.get("href")
                    candidate = urljoin(url, href)
                    parsed = urlparse(candidate)
                    if parsed.netloc == base_host and candidate not in visited and to_visit.qsize() < max_urls:
                        await to_visit.put((candidate, depth + 1))
                for tag in soup.find_all(["form"], action=True):
                    action = tag.get("action")
                    candidate = urljoin(url, action)
                    parsed = urlparse(candidate)
                    if parsed.netloc == base_host and candidate not in visited and to_visit.qsize() < max_urls:
                        await to_visit.put((candidate, depth + 1))
            except Exception as exc:  # noqa: BLE001
                message = str(exc).strip() or exc.__class__.__name__
                if message not in errors:
                    errors.append(message)

        async def worker(client: httpx.AsyncClient):
            while True:
                try:
                    url, depth = await asyncio.wait_for(to_visit.get(), timeout=0.2)
                except asyncio.TimeoutError:
                    return
                try:
                    await fetch_url(client, url, depth)
                finally:
                    to_visit.task_done()

        async with httpx.AsyncClient(
            timeout=client_timeout,
            follow_redirects=True,
            verify=settings.HTTP_VERIFY_TLS,
            limits=limits,
        ) as client:
            workers = [asyncio.create_task(worker(client)) for _ in range(concurrency)]
            await to_visit.join()
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        duration = (datetime.now() - start_ts).total_seconds()

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            timestamp=start_ts,
            duration=duration,
            success=True,
            findings=findings,
            raw_output=f"visited={metadata['visited']}",
            errors=errors,
            metadata=metadata,
        )
