"""
Compatibility shim for environments where `browser_cookie3` is unavailable.

Wapiti can import this package even when browser-cookie extraction is not used.
"""

from __future__ import annotations

from http.cookiejar import CookieJar


def _empty_cookiejar(*_args, **_kwargs) -> CookieJar:  # pragma: no cover
    return CookieJar()


chrome = _empty_cookiejar
chromium = _empty_cookiejar
firefox = _empty_cookiejar
edge = _empty_cookiejar
opera = _empty_cookiejar
safari = _empty_cookiejar
brave = _empty_cookiejar
vivaldi = _empty_cookiejar
