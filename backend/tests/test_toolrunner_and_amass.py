from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.scanner import ToolRunner
from app.tools.base import BaseToolWrapper, ToolCategory, ToolResult
from app.tools.discovery.amass_wrapper import AmassWrapper


class SlowToolWrapper(BaseToolWrapper):
    name = "slow_tool_override"
    category = ToolCategory.DISCOVERY

    def __init__(self, config=None):
        self.config = config or {}
        self.logger = None

    def run(self, target: str, options=None) -> ToolResult:
        import time

        time.sleep(2)
        return ToolResult(
            tool_name=self.name,
            category="discovery",
            target=target,
            timestamp=datetime.now(),
            duration=2.0,
            success=True,
            findings=[],
            raw_output="",
            errors=[],
        )

    def parse_output(self, raw_output: str):
        return []


@pytest.mark.asyncio
async def test_tool_runner_applies_minimum_tool_timeout_floor():
    runner = ToolRunner(timeout=10)
    success, findings, error = await runner.run_tool(
        SlowToolWrapper,
        "https://example.com",
        options={"tool_timeout": 1},
    )

    # ToolRunner clamps too-low timeouts to 5 seconds.
    assert success is True
    assert findings == []
    assert error is None


def test_amass_resolves_oa_json_output(workspace_tmp_dir: Path):
    with patch.object(AmassWrapper, "_validate_dependencies", lambda self: None):
        wrapper = AmassWrapper(config={"path": "amass"})

    output_dir = workspace_tmp_dir / "amass_output"
    output_dir.mkdir()
    requested_json = output_dir / "amass_123.json"
    oa_json = output_dir / "amass_123.json"
    oa_json.write_text('{"name":"sub.example.com","domain":"example.com"}\n', encoding="utf-8")

    resolved = wrapper._resolve_amass_json_output(requested_json.with_suffix(""), requested_json)

    assert resolved == oa_json


def test_amass_run_uses_json_flag(workspace_tmp_dir: Path):
    with patch.object(AmassWrapper, "_validate_dependencies", lambda self: None):
        wrapper = AmassWrapper(config={"path": "amass"})

    captured = {}

    def fake_exec(command, timeout=600):
        captured["command"] = command
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    wrapper._execute_command = fake_exec  # type: ignore[method-assign]

    result, command = wrapper._run_amass("example.com", workspace_tmp_dir / "amass_test.json", {"active": False})

    assert result.returncode == 0
    assert command == captured["command"]
    assert "-json" in command
    assert "-oA" not in command


def test_amass_parse_text_output_extracts_subdomains():
    with patch.object(AmassWrapper, "_validate_dependencies", lambda self: None):
        wrapper = AmassWrapper(config={"path": "amass"})

    raw = "www.example.com\napi.example.com\nwww.example.com"
    findings = wrapper.parse_text_output(raw, "example.com")

    affected = sorted(f.affected_url for f in findings)
    assert affected == ["api.example.com", "www.example.com"]


def test_amass_falls_back_to_oa_when_json_flag_is_unsupported(workspace_tmp_dir: Path):
    with patch.object(AmassWrapper, "_validate_dependencies", lambda self: None):
        wrapper = AmassWrapper(config={"path": "amass"})

    calls = []

    def fake_exec(command, timeout=600):
        calls.append(command)
        if "-json" in command:
            return SimpleNamespace(stdout="", stderr="flag provided but not defined: -json", returncode=1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    wrapper._execute_command = fake_exec  # type: ignore[method-assign]

    result, command = wrapper._run_amass("example.com", workspace_tmp_dir / "amass_test.json", {"active": False})

    assert result.returncode == 0
    assert any("-json" in cmd for cmd in calls)
    assert "-oA" in command


def test_amass_skips_second_json_attempt_after_flag_detection(workspace_tmp_dir: Path):
    with patch.object(AmassWrapper, "_validate_dependencies", lambda self: None):
        wrapper = AmassWrapper(config={"path": "amass"})

    calls = []

    def fake_exec(command, timeout=600):
        calls.append(command)
        if "-json" in command:
            return SimpleNamespace(stdout="", stderr="flag provided but not defined: -json", returncode=1)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    wrapper._execute_command = fake_exec  # type: ignore[method-assign]

    result, command = wrapper._run_amass("example.com", workspace_tmp_dir / "amass_test.json", {"active": True})

    json_attempts = [cmd for cmd in calls if "-json" in cmd]
    assert result.returncode == 0
    assert len(json_attempts) == 1
    assert "-oA" in command


def test_nikto_like_wrappers_capture_nonzero_exit_detail():
    from app.tools.discovery.nikto_wrapper import NiktoWrapper

    wrapper = NiktoWrapper(validate_binary=False)
    sample = '{"vulnerabilities":[]}'

    def fake_exec(cmd, timeout=300):
        return SimpleNamespace(stdout=sample, stderr="network issue", returncode=1)

    wrapper._execute_command = fake_exec  # type: ignore[method-assign]
    result = wrapper.run("http://target", {})

    assert result.success is False
    assert result.errors
    assert "network issue" in result.errors[0]
