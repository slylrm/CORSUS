"""
Minimal Playwright compatibility shim.
"""

from __future__ import annotations


class Error(RuntimeError):
    pass


class _UnavailablePlaywright:
    async def __aenter__(self):
        raise Error("Playwright is not available in this environment.")

    async def __aexit__(self, exc_type, exc, tb):
        return False


def async_playwright():  # pragma: no cover
    return _UnavailablePlaywright()
