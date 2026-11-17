from unittest.mock import patch

from app.tools.discovery.zap_scanner_wrapper import ZapScannerWrapper
from app.tools.registry import build_tool_options


def test_build_tool_options_tunes_dir_brute_for_deep_scan():
    opts = build_tool_options("dir_brute", "deep")
    assert opts["timeout"] == 6
    assert opts["concurrency"] == 28
    assert opts["max_paths"] == 32


def test_build_tool_options_tunes_crawler_for_standard_scan():
    opts = build_tool_options("crawler", "standard")
    assert opts["max_depth"] == 1
    assert opts["max_urls"] == 30
    assert opts["concurrency"] == 12


def test_build_tool_options_disables_default_zap_active_scan():
    opts = build_tool_options("owasp_zap", "deep")
    assert opts["active_scan"] is False


def test_zap_context_parser_accepts_string_context_id():
    wrapper = ZapScannerWrapper(validate_binary=False)
    with patch.object(wrapper, "_get_json") as mock_get_json:
        mock_get_json.side_effect = [
            {"contextList": ["scanner_context"]},
            {},
            {"context": "0"},
        ]
        context_id = wrapper._ensure_context("http://127.0.0.1:8080", "scanner_context", "https://example.com", {})
    assert context_id == "0"
