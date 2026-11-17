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
        max_paths: int = 6000,
        max_variants_per_seed: int = 4,
        early_stop_streak: int = 220,
        min_early_stop_samples: int = 260,
    ) -> None:
        self.wordlist_path = wordlist_path
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.max_paths = max(64, int(max_paths))
        self.max_variants_per_seed = max(1, min(int(max_variants_per_seed), 8))
        self.early_stop_streak = max(50, int(early_stop_streak))
        self.min_early_stop_samples = max(100, int(min_early_stop_samples))

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
        paths = self._build_paths(
            wordlist,
            max_paths=self.max_paths,
            max_variants_per_seed=self.max_variants_per_seed,
        )
        if not paths:
            if progress_callback:
                progress_callback(1.0, "Dizin taramasi icin kelime bulunamadi")
            return {"paths_tested": 0, "findings": []}

        semaphore = asyncio.Semaphore(self.max_concurrency)
        findings: list[dict] = []
        total = len(paths)
        completed = 0
        consecutive_misses = 0
        early_stopped = False
        baselines = await self._collect_not_found_baselines(base_url, session)
        redirect_not_found_cache: dict[str, bool] = {}
        request_timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=min(2.5, self.timeout),
            sock_read=min(3.5, self.timeout),
        )

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
                            timeout=request_timeout,
                        ) as response:
                            status = response.status
                            if status in {200, 201, 202, 204, 206, 301, 302, 307, 308, 401, 403, 405}:
                                location = response.headers.get("Location")
                                content_type = response.headers.get("Content-Type", "")
                                content_length_header = response.headers.get("Content-Length")
                                content_length = None
                                if content_length_header:
                                    try:
                                        content_length = int(content_length_header)
                                    except Exception:
                                        content_length = None

                                text = ""
                                if status in {200, 201, 202, 301, 302}:
                                    body_preview = await response.content.read(4096)
                                    text = body_preview.decode(errors="ignore")
                                    if content_length is None:
                                        content_length = len(body_preview)

                                if status in {301, 302} and location:
                                    redirected_url = urljoin(str(response.url), location)
                                    cache_key = redirected_url.rstrip("/")
                                    if cache_key in redirect_not_found_cache:
                                        if redirect_not_found_cache[cache_key]:
                                            return None
                                    else:
                                        not_found_redirect = await self._redirect_looks_not_found(
                                            redirected_url,
                                            base_url,
                                            session,
                                            baselines,
                                        )
                                        redirect_not_found_cache[cache_key] = not_found_redirect
                                        if not_found_redirect:
                                            return None

                                if status in {200, 201, 202} and self._is_soft_404(
                                    status=status,
                                    text=text,
                                    content_type=content_type,
                                    location=location,
                                    baselines=baselines,
                                ):
                                    return None

                                if content_length is None:
                                    content_length = 0

                                if status in {301, 302} and not location:
                                        return None

                                return {
                                    "path": "/" + path.lstrip("/"),
                                    "url": str(response.url),
                                    "status": status,
                                    "location": location,
                                    "content_length": content_length,
                                    "content_type": content_type,
                                    "soft_404": False,
                                }
                            return None
                    except Exception:
                        if attempt >= self.retries:
                            return None
                        await asyncio.sleep(0.2 * (attempt + 1))
            return None

        queue: asyncio.Queue[str] = asyncio.Queue()
        for path in paths:
            queue.put_nowait(path)

        async def worker() -> None:
            nonlocal completed, consecutive_misses, early_stopped
            while True:
                if early_stopped:
                    return

                try:
                    path = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                try:
                    result = await probe(path)
                    completed += 1

                    if result:
                        findings.append(result)
                        consecutive_misses = 0
                    else:
                        consecutive_misses += 1

                    hit_ratio = len(findings) / completed if completed else 0.0
                    if (
                        completed >= min(self.min_early_stop_samples, total)
                        and consecutive_misses >= self.early_stop_streak
                        and hit_ratio <= 0.03
                    ):
                        early_stopped = True

                        # Drain remaining queue so queue.join() can finish cleanly.
                        while True:
                            try:
                                queue.get_nowait()
                                queue.task_done()
                            except asyncio.QueueEmpty:
                                break

                        if progress_callback:
                            progress_callback(completed / total, f"Taranan dizinler {completed}/{total} (erken durdurma)")
                        return

                    if progress_callback:
                        progress_callback(completed / total, f"Taranan dizinler {completed}/{total}")
                finally:
                    queue.task_done()

        worker_count = max(1, min(self.max_concurrency, total))
        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        await queue.join()
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        findings.sort(key=lambda item: (item["status"], item["path"]))
        return {
            "paths_tested": completed,
            "paths_planned": total,
            "early_stopped": early_stopped,
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
                    timeout=aiohttp.ClientTimeout(
                        total=self.timeout,
                        connect=min(2.5, self.timeout),
                        sock_read=min(3.5, self.timeout),
                    ),
                ) as response:
                    body_preview = await response.content.read(4096)
                    text = body_preview.decode(errors="ignore")
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
                timeout=aiohttp.ClientTimeout(
                    total=self.timeout,
                    connect=min(2.5, self.timeout),
                    sock_read=min(3.5, self.timeout),
                ),
            ) as response:
                body_preview = await response.content.read(4096)
                text = body_preview.decode(errors="ignore")
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
    def _build_paths(
        wordlist: list[str],
        *,
        max_paths: int = 6000,
        max_variants_per_seed: int = 4,
    ) -> list[str]:
        seeds = [word.lstrip("/").strip() for word in wordlist if str(word).strip()]
        variants = ["", "/", ".php", ".html", ".json", ".bak", ".old", ".zip"]
        max_paths = max(64, int(max_paths))
        max_variants_per_seed = max(1, min(int(max_variants_per_seed), len(variants)))
        selected_variants = variants[:max_variants_per_seed]
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

        def add_candidate(candidate: str) -> bool:
            normalized = candidate.lstrip("/").strip()
            if not normalized or normalized in seen:
                return False
            seen.add(normalized)
            out.append(normalized)
            return len(out) >= max_paths

        core_variants = selected_variants[: min(2, len(selected_variants))]
        extension_variants = selected_variants[len(core_variants):]

        for seed in seeds:
            if not seed:
                continue
            for variant in core_variants:
                if add_candidate(seed + variant):
                    return out

        if extension_variants:
            extension_seed_cap = min(
                len(seeds),
                max(200, max_paths // max(1, len(extension_variants) + 2)),
            )
            for variant in extension_variants:
                for seed in seeds[:extension_seed_cap]:
                    if add_candidate(seed + variant):
                        return out

        for candidate in extra:
            if add_candidate(candidate):
                break
        return out

    @staticmethod
    def _random_path(length: int = 18) -> str:
        alphabet = string.ascii_lowercase + string.digits
        token = "".join(random.choice(alphabet) for _ in range(length))
        return f"not-found-{token}"
