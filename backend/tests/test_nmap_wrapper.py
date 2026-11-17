from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.tools.discovery.nmap_wrapper import NmapWrapper


def _build_wrapper() -> NmapWrapper:
    with patch.object(NmapWrapper, "_validate_dependencies", return_value=None):
        return NmapWrapper()


def test_parse_xml_output_handles_truncated_xml():
    wrapper = _build_wrapper()
    xml_file = Path("backend/tests/_tmp_truncated_nmap.xml")
    xml_file.write_text("<nmaprun><host><ports><port portid='80'></port>", encoding="utf-8")
    try:
        findings = wrapper.parse_xml_output(xml_file)
        assert findings == []
    finally:
        if xml_file.exists():
            xml_file.unlink()


def test_parse_output_extracts_open_ports_from_stdout():
    wrapper = _build_wrapper()
    raw_output = """
    Starting Nmap 7.94
    PORT     STATE SERVICE
    80/tcp   open  http
    443/tcp  open  https
    """

    findings = wrapper.parse_output(raw_output)

    assert len(findings) == 2
    assert findings[0].title == "Open Port: 80/tcp"


def test_fast_scan_with_explicit_ports_does_not_use_fast_flag():
    wrapper = _build_wrapper()
    captured = {}

    def fake_exec(command, timeout=300):
        captured["command"] = command
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    wrapper._execute_command = fake_exec  # type: ignore[method-assign]

    result = wrapper.run("example.com", {"scan_type": "fast", "ports": "80,443"})

    assert result.success is True
    assert "-p" in captured["command"]
    assert "-F" not in captured["command"]
