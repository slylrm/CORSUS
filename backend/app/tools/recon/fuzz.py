from __future__ import annotations

import asyncio
import random
import re
import string
from difflib import SequenceMatcher
from typing import Callable
from urllib.parse import urljoin, urlparse

import aiohttp

from .utils import load_wordlist


ProgressCallback = Callable[[float, str], None]


class DirectoryFuzzer:
    def __init__(
        self,
        wordlist_path: str,
        *,
        max_concurrency: int = 40,
        timeout: float = 8.0,
        retries: int = 1,
        delay: float = 0.02,
    ) -> None:
        self.wordlist_path = wordlist_path
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay

    async def fuzz(
        self,
        base_url: str,
        session: aiohttp.ClientSession,
        progress_callback: ProgressCallback | None = None,
    ) -> dict:
        wordlist = load_wordlist(
            self.wordlist_path,
            fallback=[
                "admin",
                "login",
                "dashboard",
                "api",
                "robots.txt",
                "sitemap.xml",
            ],
        )
        paths = self._build_paths(wordlist)
        if not paths:
            if progress_callback:
                progress_callback(1.0, "Dizin taramasi icin kelime bulunamadi")
            return {"paths_tested": 0, "findings": []}

        semaphore = asyncio.Semaphore(self.max_concurrency)
        findings: list[dict] = []
        total = len(paths)
        completed = 0
        baselines = await self._collect_not_found_baselines(base_url, session)

        async def probe(path: str) -> dict | None:
            url = urljoin(base_url.rstrip("/") + "/", path)
            async with semaphore:
                for attempt in range(self.retries + 1):
                    try:
                        if self.delay:
                            await asyncio.sleep(self.delay)
                        async with session.get(
                            url,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ) as response:
                            status = response.status
                            if status in {200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403, 405}:
                                text = await response.text(errors="ignore")
                                location = response.headers.get("Location")
                                content_length = response.headers.get("Content-Length")

                                if status in {301, 302} and location:
                                    redirected_url = urljoin(str(response.url), location)
                                    if await self._redirect_looks_not_found(redirected_url, base_url, session, baselines):
                                        return None

                                if self._is_soft_404(
                                    status=status,
                                    text=text,
                                    content_type=response.headers.get("Content-Type", ""),
                                    location=location,
                                    baselines=baselines,
                                ):
                                    return None
                                return {
                                    "path": "/" + path.lstrip("/"),
                                    "url": str(response.url),
                                    "status": status,
                                    "location": location,
                                    "content_length": content_length,
                                    "content_type": response.headers.get("Content-Type"),
                                    "soft_404": False,
                                }
                            return None
                    except Exception:
                        if attempt >= self.retries:
                            return None
                        await asyncio.sleep(0.2 * (attempt + 1))
            return None

        tasks = [asyncio.create_task(probe(path)) for path in paths]
        for finished in asyncio.as_completed(tasks):
            result = await finished
            completed += 1
            if result:
                findings.append(result)
            if progress_callback:
                progress_callback(completed / total, f"Taranan dizinler {completed}/{total}")

        findings.sort(key=lambda item: (item["status"], item["path"]))
        return {
            "paths_tested": total,
            "findings": findings,
            "baseline_not_found_signatures": len(baselines),
        }

    async def _collect_not_found_baselines(self, base_url: str, session: aiohttp.ClientSession) -> list[dict]:
        baselines: list[dict] = []
        for _ in range(2):
            probe_path = "/" + self._random_path()
            url = urljoin(base_url.rstrip("/") + "/", probe_path.lstrip("/"))
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as response:
                    text = await response.text(errors="ignore")
                    baselines.append(
                        {
                            "status": response.status,
                            "location": response.headers.get("Location"),
                            "sig": self._html_signature(text),
                            "text": text[:2500],
                        }
                    )
            except Exception:
                continue
        return baselines

    def _is_soft_404(
        self,
        *,
        status: int,
        text: str,
        content_type: str,
        location: str | None,
        baselines: list[dict],
    ) -> bool:
        if status == 403:
            return False

        normalized = text.lower()
        if "text/html" not in (content_type or "").lower() and status in {200, 301, 302}:
            return False

        signature = self._html_signature(normalized)
        not_found_markers = (
            "404",
            "not found",
            "bulunamadi",
            "page not found",
            "does not exist",
        )
        marker_hit = any(marker in normalized for marker in not_found_markers)

        for baseline in baselines:
            if status in {301, 302} and baseline.get("location") and baseline.get("location") == location:
                return True

            if baseline.get("sig") == signature and signature:
                return True

            ratio = SequenceMatcher(None, normalized[:2500], str(baseline.get("text", ""))[:2500]).ratio()
            if ratio >= 0.92:
                return True

        if marker_hit and status == 200:
            return True
        return False

    async def _redirect_looks_not_found(
        self,
        redirected_url: str,
        base_url: str,
        session: aiohttp.ClientSession,
        baselines: list[dict],
    ) -> bool:
        parsed_target = urlparse(redirected_url)
        parsed_base = urlparse(base_url)
        if parsed_target.netloc and parsed_target.netloc != parsed_base.netloc:
            return False
        try:
            async with session.get(
                redirected_url,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as response:
                text = await response.text(errors="ignore")
                return self._is_soft_404(
                    status=response.status,
                    text=text,
                    content_type=response.headers.get("Content-Type", ""),
                    location=response.headers.get("Location"),
                    baselines=baselines,
                )
        except Exception:
            return False

    @staticmethod
    def _html_signature(text: str) -> str:
        stripped = re.sub(r"\s+", " ", (text or "").strip().lower())
        title_match = re.search(r"<title>(.*?)</title>", stripped)
        title = title_match.group(1) if title_match else ""
        snippet = stripped[:700]
        return f"{title}|{snippet}"

    @staticmethod
    def _build_paths(wordlist: list[str]) -> list[str]:
        seeds = [word.lstrip("/").strip() for word in wordlist if str(word).strip()]
        variants = ["", "/", ".php", ".html", ".json", ".bak", ".old", ".zip"]
        extra = [
            "admin/",
            "api/v1/",
            "api/v2/",
            ".git/HEAD",
            ".env",
            "composer.json",
            "package.json",
            "config.php",
            "server-status",
            "actuator/health",
            "swagger/index.html",
            "openapi.json",
        ]

        out: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            if not seed:
                continue
            for variant in variants:
                candidate = (seed + variant).lstrip("/")
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    out.append(candidate)
        for candidate in extra:
            normalized = candidate.lstrip("/")
            if normalized not in seen:
                seen.add(normalized)
                out.append(normalized)
        return out

    @staticmethod
    def _random_path(length: int = 18) -> str:
        alphabet = string.ascii_lowercase + string.digits
        token = "".join(random.choice(alphabet) for _ in range(length))
        return f"not-found-{token}"
