from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from app.tools.container.trivy_wrapper import TrivyWrapper
from app.tools.discovery.tech_fingerprint import TechFingerprintWrapper
from app.tools.registry import build_tool_options


def test_build_tool_options_aligns_trivy_inner_and_outer_timeouts():
    opts = build_tool_options("trivy", "deep")

    assert opts["scan_type"] == "fs"
    assert opts["timeout"] == 300
    assert opts["tool_timeout"] == 420
    assert opts["scanners"] == "vuln"
    assert opts["skip_version_check"] is True
    assert opts["quiet"] is True
    assert opts["tool_timeout"] > opts["timeout"]


def test_build_tool_options_sets_fingerprint_connect_retry_profile():
    opts = build_tool_options("fingerprint", "deep")

    assert opts["timeout"] == 12
    assert opts["connect_timeout"] == 7
    assert opts["connect_retries"] == 2


def test_build_tool_options_aligns_nikto_inner_and_outer_timeouts():
    opts = build_tool_options("nikto", "deep")

    assert opts["timeout"] == 25
    assert opts["tool_timeout"] == 420
    assert opts["tool_timeout"] > opts["timeout"]


def test_build_tool_options_aligns_wapiti_minutes_with_outer_timeout():
    opts = build_tool_options("wapiti", "deep")

    assert opts["max_scan_time"] == 10
    assert opts["tool_timeout"] == (opts["max_scan_time"] * 60) + 180
    assert opts["tool_timeout"] > opts["max_scan_time"] * 60


def test_build_tool_options_sets_amass_longer_deep_timeout_budget():
    opts = build_tool_options("amass", "deep")

    assert opts["active"] is False
    assert opts["tool_timeout"] == 720


def test_build_tool_options_sets_nuclei_deep_retry_timeout_profile():
    opts = build_tool_options("nuclei", "deep")

    assert opts["severity"] == "info,low,medium,high,critical"
    assert opts["timeout"] == 180
    assert opts["tool_timeout"] == 480
    assert opts["retry_on_timeout"] is True
    assert opts["request_timeout"] == 15
    assert opts["protocols"] == "http,ssl"
    assert opts["exclude_tags"] == "fuzz,dos,bruteforce"
    assert opts["automatic_scan"] is True


@pytest.mark.asyncio
async def test_fingerprint_connect_timeout_is_non_fatal_with_retry():
    calls = {"count": 0}

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, _url):
            calls["count"] += 1
            raise httpx.ConnectTimeout("ConnectTimeout")

    wrapper = TechFingerprintWrapper()

    with patch("app.tools.discovery.tech_fingerprint.httpx.AsyncClient", FakeAsyncClient):
        result = await wrapper.run("https://example.com", {"timeout": 8, "connect_retries": 1})

    assert result.success is True
    assert result.errors == []
    assert result.metadata.get("degraded") is True
    assert "request_error" in result.metadata
    assert calls["count"] == 2


def test_trivy_wrapper_uses_option_timeout_for_subprocess_and_cli():
    with patch.object(TrivyWrapper, "_validate_dependencies", lambda self: None):
        wrapper = TrivyWrapper(config={"path": "trivy"})

    captured = {}

    def fake_execute(command, timeout=300):
        captured["command"] = command
        captured["timeout"] = timeout
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    wrapper._execute_command = fake_execute  # type: ignore[method-assign]

    result = wrapper.run("C:/repo", {"scan_type": "fs", "timeout": 180})

    assert result.success is True
    assert captured["timeout"] == 195
    assert "--timeout" in captured["command"]
    assert "--scanners" in captured["command"]
    assert captured["command"][captured["command"].index("--scanners") + 1] == "vuln"
    assert "--skip-version-check" in captured["command"]
    assert "--quiet" in captured["command"]

    timeout_index = captured["command"].index("--timeout")
    assert captured["command"][timeout_index + 1] == "180s"


def test_trivy_wrapper_sanitizes_info_only_nonzero_exit_error():
    with patch.object(TrivyWrapper, "_validate_dependencies", lambda self: None):
        wrapper = TrivyWrapper(config={"path": "trivy"})

    def fake_execute(_command, timeout=300):
        return SimpleNamespace(
            stdout="",
            stderr=(
                "2026-04-17T18:30:46+03:00\tINFO\t[vuln] Vulnerability scanning is enabled\n"
                "2026-04-17T18:30:46+03:00\tINFO\t[secret] Secret scanning is enabled"
            ),
            returncode=1,
        )

    wrapper._execute_command = fake_execute  # type: ignore[method-assign]
    result = wrapper.run("C:/repo", {"scan_type": "fs", "timeout": 180})

    assert result.success is False
    assert result.errors == ["Trivy exited with code 1 without parsable findings"]
