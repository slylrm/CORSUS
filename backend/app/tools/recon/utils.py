from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse
import re


DEFAULT_USER_AGENT = "TaramaSecurityScanner/1.0"


@dataclass(frozen=True)
class TargetInfo:
    raw_input: str
    url: str
    scheme: str
    hostname: str
    port: int
    origin: str
    base_url: str


def normalize_target(target: str) -> TargetInfo:
    cleaned = (target or "").strip()
    if not cleaned:
        raise ValueError("Target URL cannot be empty.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    if not parsed.hostname:
        raise ValueError("Please provide a valid domain or URL.")

    scheme = parsed.scheme.lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    origin = urlunparse((scheme, netloc, "", "", "", ""))
    base_url = f"{origin}/"
    return TargetInfo(
        raw_input=cleaned,
        url=cleaned,
        scheme=scheme,
        hostname=parsed.hostname,
        port=port,
        origin=origin,
        base_url=base_url,
    )


def load_wordlist(path: str, fallback: Iterable[str] | None = None) -> list[str]:
    wordlist_path = Path(path)
    if wordlist_path.exists():
        raw_lines = wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    elif fallback is not None:
        raw_lines = list(fallback)
    else:
        raw_lines = []

    values: list[str] = []
    seen: set[str] = set()
    for line in raw_lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value not in seen:
            seen.add(value)
            values.append(value)
    return values


def safe_filename(value: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    return sanitized.strip("-") or "scan"


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def flatten_name_entries(entries) -> str:
    if not entries:
        return ""
    flattened: list[str] = []
    for group in entries:
        for key, value in group:
            flattened.append(f"{key}={value}")
    return ", ".join(flattened)
