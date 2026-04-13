from __future__ import annotations

import asyncio
import json
import random
import re
import socket
import string
from collections import defaultdict
from typing import Callable

import aiohttp

from .utils import dedupe_preserve_order, load_wordlist


ProgressCallback = Callable[[float, str], None]


class SubdomainEnumerator:
    def __init__(
        self,
        wordlist_path: str,
        *,
        max_concurrency: int = 50,
        dns_timeout: float = 3.0,
        dns_retries: int = 1,
    ) -> None:
        self.wordlist_path = wordlist_path
        self.max_concurrency = max_concurrency
        self.dns_timeout = dns_timeout
        self.dns_retries = max(0, dns_retries)

    async def enumerate(
        self,
        domain: str,
        session: aiohttp.ClientSession,
        progress_callback: ProgressCallback | None = None,
    ) -> dict:
        passive_candidates, passive_sources = await self._passive_candidates(domain, session)
        brute_candidates = self._bruteforce_candidates(domain)

        source_map: dict[str, set[str]] = defaultdict(set)
        for item, sources in passive_sources.items():
            for src in sources:
                source_map[item].add(src)
        for item in brute_candidates:
            source_map[item].add("dns-bruteforce")

        candidates = dedupe_preserve_order(passive_candidates + brute_candidates)
        wildcard_ips = await self._wildcard_ips(domain)
        live_records: list[dict] = []
        if not candidates:
            if progress_callback:
                progress_callback(1.0, "Alt alan adi adayi bulunamadi")
            return {
                "domain": domain,
                "candidates": [],
                "live_subdomains": [],
                "records": [],
                "sources": {"crtsh": 0, "dns_bruteforce": 0},
            }

        semaphore = asyncio.Semaphore(self.max_concurrency)
        total = len(candidates)
        resolved = 0

        async def resolve(candidate: str) -> dict | None:
            async with semaphore:
                for attempt in range(self.dns_retries + 1):
                    try:
                        loop = asyncio.get_running_loop()
                        infos = await asyncio.wait_for(
                            loop.getaddrinfo(candidate, None, type=socket.SOCK_STREAM),
                            timeout=self.dns_timeout,
                        )
                        ips = sorted({record[4][0] for record in infos if record and record[4]})
                        if ips:
                            if wildcard_ips and set(ips).issubset(wildcard_ips):
                                return None
                            return {
                                "subdomain": candidate,
                                "ips": ips,
                                "sources": sorted(source_map.get(candidate, {"dns-bruteforce"})),
                            }
                        return None
                    except Exception:
                        if attempt >= self.dns_retries:
                            return None
                        await asyncio.sleep(0.1 * (attempt + 1))
            return None

        tasks = [asyncio.create_task(resolve(candidate)) for candidate in candidates]
        for finished in asyncio.as_completed(tasks):
            result = await finished
            resolved += 1
            if result:
                live_records.append(result)
            if progress_callback:
                progress_callback(resolved / total, f"Cozumlenen alt alan adlari {resolved}/{total}")

        live_records = [item for item in live_records if item["subdomain"] != domain.lower()]
        live_records.sort(key=lambda item: item["subdomain"])
        live_subdomains = [item["subdomain"] for item in live_records]

        return {
            "domain": domain,
            "candidates": candidates,
            "live_subdomains": live_subdomains,
            "records": live_records,
            "sources": {
                "crtsh": sum(1 for _, s in passive_sources.items() if "crt.sh" in s),
                "bufferover": sum(1 for _, s in passive_sources.items() if "bufferover" in s),
                "certspotter": sum(1 for _, s in passive_sources.items() if "certspotter" in s),
                "dns_bruteforce": len(brute_candidates),
            },
            "wildcard_dns_detected": bool(wildcard_ips),
            "dns_retries": self.dns_retries,
        }

    async def _passive_candidates(self, domain: str, session: aiohttp.ClientSession) -> tuple[list[str], dict[str, set[str]]]:
        results = await asyncio.gather(
            self._crtsh_candidates(domain, session),
            self._bufferover_candidates(domain, session),
            self._certspotter_candidates(domain, session),
            return_exceptions=True,
        )
        source_names = ["crt.sh", "bufferover", "certspotter"]
        merged: list[str] = []
        source_map: dict[str, set[str]] = defaultdict(set)
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            for host in result:
                merged.append(host)
                source_map[host].add(source_names[idx])
        return dedupe_preserve_order(merged), source_map

    async def _crtsh_candidates(self, domain: str, session: aiohttp.ClientSession) -> list[str]:
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": "TaramaSecurityScanner/1.0"}
        try:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=25)) as response:
                raw = await response.text(errors="ignore")
                if not raw.strip():
                    return []
                payload = json.loads(raw)
        except Exception:
            return []

        domain_lower = domain.lower()
        seen: set[str] = set()
        candidates: list[str] = []
        for entry in payload:
            name_value = str(entry.get("name_value", ""))
            for value in name_value.splitlines():
                candidate = value.strip().lower().lstrip("*.")
                if not candidate or candidate in seen:
                    continue
                if candidate == domain_lower or candidate.endswith(f".{domain_lower}"):
                    seen.add(candidate)
                    candidates.append(candidate)
        return candidates

    async def _bufferover_candidates(self, domain: str, session: aiohttp.ClientSession) -> list[str]:
        url = "https://dns.bufferover.run/dns"
        params = {"q": f".{domain}"}
        headers = {"User-Agent": "TaramaSecurityScanner/1.0"}
        try:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=18)) as response:
                payload = await response.json(content_type=None)
        except Exception:
            return []

        out: list[str] = []
        seen: set[str] = set()
        for key in ("FDNS_A", "RDNS"):
            for row in payload.get(key, []) or []:
                parts = str(row).split(",")
                if not parts:
                    continue
                host = parts[-1].strip().lower().lstrip("*.")
                if host.endswith(f".{domain}") and host not in seen:
                    seen.add(host)
                    out.append(host)
        return out

    async def _certspotter_candidates(self, domain: str, session: aiohttp.ClientSession) -> list[str]:
        url = "https://api.certspotter.com/v1/issuances"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        headers = {"User-Agent": "TaramaSecurityScanner/1.0"}
        try:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=22)) as response:
                payload = await response.json(content_type=None)
        except Exception:
            return []

        out: list[str] = []
        seen: set[str] = set()
        for cert in payload or []:
            for name in cert.get("dns_names", []) or []:
                host = str(name).strip().lower().lstrip("*.")
                if host.endswith(f".{domain}") and host not in seen:
                    seen.add(host)
                    out.append(host)
        return out

    def _bruteforce_candidates(self, domain: str) -> list[str]:
        fallback_words = [
            "www",
            "mail",
            "dev",
            "staging",
            "test",
            "api",
            "cdn",
            "static",
        ]
        wordlist = load_wordlist(self.wordlist_path, fallback=fallback_words)
        candidates: list[str] = []
        seen: set[str] = set()
        for word in wordlist:
            cleaned = word.strip().lower().strip(".")
            if not self._is_valid_label(cleaned):
                continue
            candidate = f"{cleaned}.{domain.lower()}"
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
        return candidates

    async def _wildcard_ips(self, domain: str) -> set[str]:
        probes = [
            f"{self._random_label()}.{domain}",
            f"{self._random_label()}.{domain}",
        ]
        loop = asyncio.get_running_loop()
        resolved_sets: list[set[str]] = []
        for hostname in probes:
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
                    timeout=self.dns_timeout,
                )
                ips = {record[4][0] for record in infos if record and record[4]}
                if ips:
                    resolved_sets.append(ips)
            except Exception:
                continue

        if len(resolved_sets) < 2:
            return set()
        intersection = resolved_sets[0].intersection(*resolved_sets[1:])
        return intersection

    @staticmethod
    def _random_label(length: int = 16) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return "scan" + "".join(random.choice(alphabet) for _ in range(length))

    @staticmethod
    def _is_valid_label(value: str) -> bool:
        if not value or len(value) > 63:
            return False
        if "/" in value or " " in value:
            return False
        if value.startswith("-") or value.endswith("-"):
            return False
        return bool(re.fullmatch(r"[a-z0-9-]+", value))
