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
        max_depth = int(opts.get("max_depth", 2))
        concurrency = int(opts.get("concurrency", 5))
        timeout = int(opts.get("timeout", 30))

        parsed_root = urlparse(target)
        base_host = parsed_root.netloc

        visited: Set[str] = set()
        to_visit: asyncio.Queue[str] = asyncio.Queue()
        await to_visit.put(target)

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {"visited": 0, "discovered": []}

        sem = asyncio.Semaphore(concurrency)

        async def fetch_url(url: str, depth: int):
            if depth > max_depth:
                return
            if url in visited:
                return
            visited.add(url)
            metadata["visited"] += 1
            try:
                async with sem:
                    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                        resp = await client.get(url)
                        metadata["discovered"].append({"url": url, "status": resp.status_code})
                        # Basic tech evidence
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
                        # Parse links
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for tag in soup.find_all(["a", "link", "script"], href=True):
                            href = tag.get("href")
                            candidate = urljoin(url, href)
                            parsed = urlparse(candidate)
                            if parsed.netloc == base_host:
                                await to_visit.put((candidate, depth + 1))
                        for tag in soup.find_all(["form"], action=True):
                            action = tag.get("action")
                            candidate = urljoin(url, action)
                            parsed = urlparse(candidate)
                            if parsed.netloc == base_host:
                                await to_visit.put((candidate, depth + 1))
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        # Worker loop (BFS until queue empty)
        while not to_visit.empty():
            try:
                item = await to_visit.get()
                if isinstance(item, tuple):
                    url, depth = item
                else:
                    url, depth = item, 0
                await fetch_url(url, depth)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

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
