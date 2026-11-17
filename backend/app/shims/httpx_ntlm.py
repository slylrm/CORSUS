"""
Compatibility shim for environments where `httpx_ntlm` is unavailable.

Wapiti imports HttpNtlmAuth at module import time, even when NTLM auth
is not used. This shim prevents hard crashes in that scenario.
"""

from __future__ import annotations


class HttpNtlmAuth:  # pragma: no cover - runtime compatibility shim
    def __init__(self, *_args, **_kwargs):
        raise RuntimeError(
            "NTLM authentication support is unavailable in this environment "
            "(missing dependency: httpx_ntlm)."
        )
