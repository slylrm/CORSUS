from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.tools.discovery.nuclei_wrapper import NucleiWrapper
from app.tools.discovery.builtin_scanner_wrapper import (
    BasicInfoWrapper,
    SecurityHeadersWrapper,
    SSLScannerWrapper,
    PortScannerWrapper,
)


def _build_nuclei_wrapper() -> NucleiWrapper:
    with patch.object(NucleiWrapper, "_validate_dependencies", return_value=None):
        return NucleiWrapper()


def test_parse_json_output_supports_json_array():
    wrapper = _build_nuclei_wrapper()
    json_file = Path("backend/tests/_tmp_nuclei_array.json")
    json_file.write_text(
        """
[
  {
    "template-id": "test-template",
    "matched-at": "https://example.com",
    "info": {
      "name": "Example Exposure",
      "description": "Example issue",
      "severity": "medium",
      "classification": {"cvss-score": 5.4}
    }
  }
]
        """.strip(),
        encoding="utf-8",
    )
    try:
        findings = wrapper.parse_json_output(json_file)
        assert len(findings) == 1
        assert findings[0].title == "Example Exposure"
    finally:
        if json_file.exists():
            json_file.unlink()


def test_builtin_wrappers_expose_string_names():
    assert BasicInfoWrapper.name == "basic"
    assert SecurityHeadersWrapper.name == "headers"
    assert SSLScannerWrapper.name == "ssl"
    assert PortScannerWrapper.name == "ports"


def test_nuclei_run_uses_safe_threading_flags():
  wrapper = _build_nuclei_wrapper()
  captured = {}

  def fake_exec(command, timeout=180):
    captured["command"] = command
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run("https://example.com", {"timeout": 30})

  assert result.success is True
  assert "-c" in captured["command"]
  assert "-rl" in captured["command"]
  assert "-bs" in captured["command"]
  assert "-retries" in captured["command"]
  assert "-duc" in captured["command"]
  assert "-ni" in captured["command"]
  assert "-timeout" in captured["command"]


def test_nuclei_can_disable_optional_runtime_flags():
  wrapper = _build_nuclei_wrapper()
  captured = {}

  def fake_exec(command, timeout=180):
    captured["command"] = command
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run(
    "https://example.com",
    {
      "timeout": 30,
      "disable_update_check": False,
      "no_interactsh": False,
      "request_timeout": 20,
    },
  )
  output_file = Path(result.metadata["json_output"])

  try:
    assert result.success is True
    assert "-duc" not in captured["command"]
    assert "-ni" not in captured["command"]
    assert captured["command"][captured["command"].index("-timeout") + 1] == "20"
  finally:
    if output_file.exists():
      output_file.unlink()


def test_nuclei_retries_with_reduced_limits_on_thread_exhaustion():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append(command)
    if len(calls) == 1:
      return SimpleNamespace(
        stdout="",
        stderr="runtime: program exceeds 10000-thread limit\nfatal error: thread exhaustion",
        returncode=2,
      )
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run("https://example.com", {"timeout": 30, "concurrency": 20, "rate_limit": 80, "bulk_size": 25, "retries": 1})

  def value_for_flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]

  assert result.success is True
  assert len(calls) == 2
  assert value_for_flag(calls[1], "-c") == "5"
  assert value_for_flag(calls[1], "-rl") == "20"
  assert value_for_flag(calls[1], "-bs") == "5"
  assert value_for_flag(calls[1], "-retries") == "0"


def test_nuclei_retries_with_reduced_limits_on_opaque_nonzero_exit():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append(command)
    if len(calls) == 1:
      return SimpleNamespace(stdout="", stderr="", returncode=1)
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run("https://example.com", {"timeout": 30, "concurrency": 20, "rate_limit": 80, "bulk_size": 25, "retries": 1})

  def value_for_flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]

  assert result.success is True
  assert len(calls) == 2
  assert value_for_flag(calls[1], "-c") == "5"
  assert value_for_flag(calls[1], "-rl") == "20"
  assert value_for_flag(calls[1], "-bs") == "5"
  assert value_for_flag(calls[1], "-retries") == "0"


def test_nuclei_timeout_does_not_retry_by_default_and_writes_empty_json_artifact():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append(timeout)
    return SimpleNamespace(stdout="", stderr=f"Command timed out after {timeout}s", returncode=-1)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run("https://example.com", {"timeout": 30})
  output_file = Path(result.metadata["json_output"])

  try:
    assert result.success is False
    assert len(calls) == 1
    assert output_file.exists()
    assert output_file.read_text(encoding="utf-8").strip() == "[]"
  finally:
    if output_file.exists():
      output_file.unlink()


def test_nuclei_timeout_retry_is_opt_in():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append((timeout, command))
    if len(calls) == 1:
      return SimpleNamespace(stdout="", stderr=f"Command timed out after {timeout}s", returncode=-1)
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run(
    "https://example.com",
    {
      "timeout": 30,
      "tool_timeout": 240,
      "retry_on_timeout": True,
      "concurrency": 20,
      "rate_limit": 80,
      "bulk_size": 25,
      "request_timeout": 15,
    },
  )
  output_file = Path(result.metadata["json_output"])

  def value_for_flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]

  try:
    assert result.success is True
    assert len(calls) == 2
    assert calls[0][0] == 30
    assert 180 <= calls[1][0] <= 230
    assert value_for_flag(calls[1][1], "-c") == "3"
    assert value_for_flag(calls[1][1], "-rl") == "10"
    assert value_for_flag(calls[1][1], "-bs") == "3"
    assert value_for_flag(calls[1][1], "-timeout") == "10"
  finally:
    if output_file.exists():
      output_file.unlink()


def test_nuclei_optional_scope_flags_are_applied():
  wrapper = _build_nuclei_wrapper()
  captured = {}

  def fake_exec(command, timeout=180):
    captured["command"] = command
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run(
    "https://example.com",
    {
      "timeout": 30,
      "protocols": "http,ssl",
      "exclude_tags": "fuzz,dos",
      "automatic_scan": True,
    },
  )
  output_file = Path(result.metadata["json_output"])

  try:
    assert result.success is True
    assert "-pt" in captured["command"]
    assert captured["command"][captured["command"].index("-pt") + 1] == "http,ssl"
    assert "-etags" in captured["command"]
    assert captured["command"][captured["command"].index("-etags") + 1] == "fuzz,dos"
    assert "-as" in captured["command"]
  finally:
    if output_file.exists():
      output_file.unlink()


def test_nuclei_hard_stability_retry_recovers_from_opaque_nonzero_exit():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append(command)
    if len(calls) == 1:
      return SimpleNamespace(stdout="", stderr="", returncode=1)
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run(
    "https://example.com",
    {
      "timeout": 60,
      "tool_timeout": 120,
      "retry_opaque_exit": False,
      "hard_stability_retry": True,
      "concurrency": 1,
      "rate_limit": 5,
      "bulk_size": 1,
      "automatic_scan": True,
    },
  )
  output_file = Path(result.metadata["json_output"])

  def value_for_flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]

  try:
    assert result.success is True
    assert len(calls) == 2
    assert "-as" not in calls[1]
    assert "-tags" in calls[1]
    assert value_for_flag(calls[1], "-tags") == "cve,misconfig,exposure"
    assert value_for_flag(calls[1], "-c") == "1"
    assert value_for_flag(calls[1], "-headc") == "1"
    assert value_for_flag(calls[1], "-hbs") == "1"
    assert value_for_flag(calls[1], "-pc") == "1"
  finally:
    if output_file.exists():
      output_file.unlink()


def test_parse_json_output_tolerates_malformed_json_lines():
  wrapper = _build_nuclei_wrapper()
  json_file = Path("backend/tests/_tmp_nuclei_malformed_jsonl.json")
  json_file.write_text(
    (
      '{"template-id":"valid-template","matched-at":"https://example.com","info":{"name":"Valid Finding","severity":"low"}}\n'
      '{"template-id":"broken-template","matched-at":"https://example.com","info":\n'
    ),
    encoding="utf-8",
  )

  try:
    findings = wrapper.parse_json_output(json_file)
    assert len(findings) == 1
    assert findings[0].title == "Valid Finding"
  finally:
    if json_file.exists():
      json_file.unlink()


def test_nuclei_timeout_fallback_does_not_escalate_limits_before_hard_safe_retry():
  wrapper = _build_nuclei_wrapper()
  calls = []

  def fake_exec(command, timeout=180):
    calls.append(command)
    if len(calls) == 1:
      return SimpleNamespace(stdout="", stderr=f"Command timed out after {timeout}s", returncode=-1)
    if len(calls) == 2:
      return SimpleNamespace(stdout="", stderr="", returncode=1)
    return SimpleNamespace(stdout="", stderr="", returncode=0)

  wrapper._execute_command = fake_exec  # type: ignore[method-assign]

  result = wrapper.run(
    "https://example.com",
    {
      "timeout": 30,
      "tool_timeout": 120,
      "retry_on_timeout": True,
      "retry_opaque_exit": True,
      "hard_stability_retry": True,
      "concurrency": 4,
      "rate_limit": 15,
      "bulk_size": 4,
      "retries": 1,
      "request_timeout": 15,
      "automatic_scan": True,
    },
  )
  output_file = Path(result.metadata["json_output"])

  def value_for_flag(cmd, flag):
    return cmd[cmd.index(flag) + 1]

  try:
    assert result.success is True
    assert len(calls) == 3

    # Timeout retry uses safer limits.
    assert value_for_flag(calls[1], "-c") == "3"
    assert value_for_flag(calls[1], "-rl") == "10"
    assert value_for_flag(calls[1], "-bs") == "3"
    assert value_for_flag(calls[1], "-retries") == "0"
    assert value_for_flag(calls[1], "-timeout") == "10"

    # Hard-safe retry is applied next without returning to initial aggressive limits.
    assert value_for_flag(calls[2], "-c") == "1"
    assert value_for_flag(calls[2], "-rl") == "5"
    assert value_for_flag(calls[2], "-bs") == "1"
    assert "-as" not in calls[2]
  finally:
    if output_file.exists():
      output_file.unlink()
