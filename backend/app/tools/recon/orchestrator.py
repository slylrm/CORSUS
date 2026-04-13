from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

import aiohttp

from .fingerprint import TechnologyFingerprinter
from .fuzz import DirectoryFuzzer
from .ssl_check import SSLSecurityAnalyzer
from .subdomain import SubdomainEnumerator
from .utils import DEFAULT_USER_AGENT, normalize_target


ProgressUpdate = Callable[[int, str], None]


@dataclass(slots=True)
class ScanConfig:
    target_url: str
    target_host: str
    directory_wordlist: str
    subdomain_wordlist: str = "wordlists/subdomains.txt"
    max_concurrency: int = 50
    timeout: float = 10.0
    request_delay: float = 0.02
    retries: int = 1
    dns_timeout: float = 3.0
    dns_retries: int = 1


class ProgressTracker:
    def __init__(self, update_callback: ProgressUpdate | None) -> None:
        self.update_callback = update_callback
        self.weights = {
            "subdomains": 0.35,
            "ssl": 0.20,
            "fuzz": 0.30,
            "fingerprint": 0.15,
        }
        self.stage_progress = {key: 0.0 for key in self.weights}
        self.last_message = "Starting"

    def update(self, stage: str, fraction: float, message: str) -> None:
        if stage not in self.stage_progress:
            return
        self.stage_progress[stage] = max(0.0, min(1.0, fraction))
        self.last_message = message or self.last_message
        overall = int(round(sum(self.stage_progress[name] * weight for name, weight in self.weights.items()) * 100))
        if self.update_callback:
            self.update_callback(overall, self.last_message)


class WebSecurityScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.subdomains = SubdomainEnumerator(
            config.subdomain_wordlist,
            max_concurrency=config.max_concurrency,
            dns_timeout=config.dns_timeout,
            dns_retries=config.dns_retries,
        )
        self.ssl = SSLSecurityAnalyzer(timeout=config.timeout)
        self.fuzzer = DirectoryFuzzer(
            config.directory_wordlist,
            max_concurrency=config.max_concurrency,
            timeout=config.timeout,
            retries=config.retries,
            delay=config.request_delay,
        )
        self.fingerprinter = TechnologyFingerprinter(timeout=config.timeout)

    async def run(self, progress_callback: ProgressUpdate | None = None) -> dict:
        target = normalize_target(self.config.target_url)
        tracker = ProgressTracker(progress_callback)
        tracker.update("subdomains", 0.0, "Alt alan adi taramasi basliyor")
        tracker.update("ssl", 0.0, "TLS analizi basliyor")
        tracker.update("fuzz", 0.0, "Dizin taramasi basliyor")
        tracker.update("fingerprint", 0.0, "Teknoloji tespiti basliyor")

        connector = aiohttp.TCPConnector(limit=self.config.max_concurrency * 2, ttl_dns_cache=300, ssl=False)
        timeout = aiohttp.ClientTimeout(total=None, connect=self.config.timeout, sock_read=self.config.timeout)
        errors: list[str] = []

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        ) as session:
            async def run_subdomains() -> dict:
                return await self.subdomains.enumerate(
                    target.hostname,
                    session,
                    progress_callback=lambda fraction, message: tracker.update("subdomains", fraction, message),
                )

            async def run_ssl() -> dict:
                ssl_port = target.port if target.scheme == "https" or target.port != 80 else 443
                if ssl_port <= 0:
                    ssl_port = 443
                result = await self.ssl.analyze(target.hostname, ssl_port)
                tracker.update("ssl", 1.0, "TLS analizi tamamlandi")
                return result

            async def run_fuzz() -> dict:
                result = await self.fuzzer.fuzz(
                    target.base_url,
                    session,
                    progress_callback=lambda fraction, message: tracker.update("fuzz", fraction, message),
                )
                tracker.update("fuzz", 1.0, "Dizin taramasi tamamlandi")
                return result

            async def run_fingerprint() -> dict:
                result = await self.fingerprinter.detect(
                    target.base_url,
                    session,
                    progress_callback=lambda fraction, message: tracker.update("fingerprint", fraction, message),
                )
                tracker.update("fingerprint", 1.0, "Teknoloji tespiti tamamlandi")
                return result

            results = await asyncio.gather(
                run_subdomains(),
                run_ssl(),
                run_fuzz(),
                run_fingerprint(),
                return_exceptions=True,
            )

        subdomains_result, ssl_result, fuzz_result, fingerprint_result = results
        if isinstance(subdomains_result, Exception):
            errors.append(f"Subdomain scan failed: {subdomains_result}")
            subdomains_result = {"domain": target.hostname, "candidates": [], "live_subdomains": [], "records": []}
        if isinstance(ssl_result, Exception):
            errors.append(f"SSL scan failed: {ssl_result}")
            ssl_result = {"host": target.hostname, "reachable": False, "error": str(ssl_result), "issues": []}
        if isinstance(fuzz_result, Exception):
            errors.append(f"Directory fuzzing failed: {fuzz_result}")
            fuzz_result = {"paths_tested": 0, "findings": [], "error": str(fuzz_result)}
        if isinstance(fingerprint_result, Exception):
            errors.append(f"Fingerprinting failed: {fingerprint_result}")
            fingerprint_result = {
                "url": target.base_url,
                "status": None,
                "technologies": [],
                "server_header": None,
                "headers": {},
                "error": str(fingerprint_result),
            }

        report = {
            "target": {
                "input": self.config.target_url,
                "normalized_url": target.base_url,
                "host": target.hostname,
                "scheme": target.scheme,
                "port": target.port,
            },
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "subdomains": subdomains_result,
            "ssl": ssl_result,
            "directories": fuzz_result,
            "technologies": fingerprint_result,
            "errors": errors,
        }

        tracker.update("subdomains", 1.0, "Alt alan adi taramasi tamamlandi")
        tracker.update("ssl", 1.0, "TLS analizi tamamlandi")
        tracker.update("fuzz", 1.0, "Dizin taramasi tamamlandi")
        tracker.update("fingerprint", 1.0, "Teknoloji tespiti tamamlandi")
        return report
