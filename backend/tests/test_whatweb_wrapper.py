"""
WhatWeb Wrapper - Comprehensive Test Suite

Tests for WhatWeb tool wrapper integration with ScannerEngine
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import json

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.tools.discovery.whatweb_wrapper import WhatWebWrapper
from app.tools.base import RiskLevel


class TestWhatWebWrapper:
    """Test suite for WhatWebWrapper"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.wrapper = WhatWebWrapper()
        self.target = "https://example.com"
    
    def test_initialization(self):
        """Test wrapper initialization"""
        assert self.wrapper.name == "whatweb"
        assert self.wrapper.category.value == "discovery"
        assert self.wrapper.description == "Web technology recognition tool"
        print("✓ Initialization test passed")
    
    def test_build_command_basic(self):
        """Test basic command building"""
        command = self.wrapper._build_command(self.target, {})
        
        assert "whatweb" in command[0]
        log_arg = next((c for c in command if c.startswith("--log=json=")), None)
        assert log_arg is not None
        log_path = Path(log_arg.split("=", 2)[-1])
        assert log_path.suffix == ".json"
        assert "--timeout" in command
        assert self.target in command
        print("✓ Basic command build test passed")
    
    def test_build_command_with_options(self):
        """Test command building with options"""
        options = {
            "aggressive": True,
            "follow_redirects": True,
            "user_agent": "Custom UA",
            "proxy": "http://proxy:8080",
            "timeout": 60
        }
        
        command = self.wrapper._build_command(self.target, options)
        
        assert "-a" in command  # aggressive
        assert "--follow-redirect" in command
        assert "Custom UA" in command
        assert "http://proxy:8080" in command
        print("✓ Command with options test passed")
    
    def test_is_version(self):
        """Test version detection"""
        assert self.wrapper._is_version("1.2.3") is True
        assert self.wrapper._is_version("4.9.8") is True
        assert self.wrapper._is_version("10") is True
        assert self.wrapper._is_version("WordPress") is False
        assert self.wrapper._is_version("Entry Point") is False
        print("✓ Version detection test passed")
    
    def test_calculate_confidence(self):
        """Test confidence calculation"""
        # With versions and headers
        conf1 = self.wrapper._calculate_confidence(
            "WordPress",
            ["4.9.8"],
            {"X-Powered-By": "WordPress"},
            "WordPress content"
        )
        
        assert 0.8 <= conf1 <= 1.0, f"Expected high confidence, got {conf1}"
        
        # Without versions or headers
        conf2 = self.wrapper._calculate_confidence(
            "WordPress",
            [],
            {},
            ""
        )
        
        assert 0.5 <= conf2 < 0.8, f"Expected medium confidence, got {conf2}"
        print(f"✓ Confidence calculation test passed (conf1={conf1}, conf2={conf2})")
    
    def test_calculate_confidence_from_methods(self):
        """Test confidence from detection methods"""
        # High-confidence methods
        conf1 = self.wrapper._calculate_confidence_from_methods(
            ["Meta-Generator", "X-Powered-By"]
        )
        assert conf1 >= 0.85
        
        # Medium-confidence methods
        conf2 = self.wrapper._calculate_confidence_from_methods(
            ["HTML", "Cookies"]
        )
        assert 0.6 <= conf2 < 0.8
        
        # Empty methods
        conf3 = self.wrapper._calculate_confidence_from_methods([])
        assert conf3 == 0.5
        
        print(f"✓ Confidence from methods test passed")
    
    def test_parse_text_line(self):
        """Test text line parsing"""
        line = "WordPress[4.9.8, Entry Point Detection, Meta-Generator]"
        
        result = self.wrapper._parse_text_line(line, self.target)
        
        assert result is not None
        assert result["title"] == "Web Technology Detected: WordPress"
        assert "4.9.8" in result["evidence"]["versions"]
        assert result["risk_level"] == "info"
        assert result["confidence_score"] >= 0.5
        print("✓ Text line parsing test passed")
    
    def test_parse_text_line_invalid(self):
        """Test invalid text line parsing"""
        # Invalid lines should return None or low confidence
        result1 = self.wrapper._parse_text_line("Random text", self.target)
        assert result1 is None or result1["confidence_score"] < 0.5
        
        result2 = self.wrapper._parse_text_line("", self.target)
        assert result2 is None or result2["confidence_score"] < 0.5
        
        result3 = self.wrapper._parse_text_line("NoData[]", self.target)
        assert result3 is None or result3["confidence_score"] < 0.5
        
        print("✓ Invalid text line parsing test passed")
    
    def test_parse_text_output(self):
        """Test text output parsing"""
        text_output = """
https://example.com [WordPress[4.9.8, Meta-Generator], Nginx[1.15.0, Server]]
"""
        
        findings = self.wrapper._parse_text_output(text_output, self.target)
        
        # Should have at least WordPress finding
        wordpress_findings = [f for f in findings if "WordPress" in f.get("title", "")]
        assert len(wordpress_findings) >= 1, f"No WordPress findings found in {len(findings)} findings"
        print(f"✓ Text output parsing test passed ({len(findings)} findings)")
    
    def test_parse_json_output(self):
        """Test JSON output parsing"""
        json_data = {
            "plugins": {
                "WordPress": {
                    "versions": ["5.0"],
                    "headers": {"X-Powered-By": "WordPress"},
                    "string": "wp-content"
                },
                "Apache": {
                    "versions": ["2.4.41"],
                    "headers": {"Server": "Apache/2.4.41"},
                    "string": ""
                }
            }
        }
        
        findings = self.wrapper._parse_json_output(json_data, self.target)
        
        assert len(findings) >= 2
        assert any(f["evidence"]["technology"] == "WordPress" for f in findings)
        assert any(f["evidence"]["technology"] == "Apache" for f in findings)
        
        for finding in findings:
            assert "title" in finding
            assert "description" in finding
            assert "risk_level" in finding
            assert "confidence_score" in finding
            assert 0 <= finding["confidence_score"] <= 1.0
        
        print(f"✓ JSON output parsing test passed ({len(findings)} findings)")
    
    def test_filter_low_confidence(self):
        """Test filtering of low-confidence findings"""
        json_data = {
            "plugins": {
                "HighConfidence": {
                    "versions": ["1.0"],
                    "headers": {"X-Powered-By": "HighConfidence"},
                    "string": "Evidence"
                },
                "LowConfidence": {
                    "versions": [],
                    "headers": {},
                    "string": ""
                }
            }
        }
        
        findings = self.wrapper._parse_json_output(json_data, self.target)
        
        # Low confidence findings should be filtered out
        for finding in findings:
            assert finding["confidence_score"] >= 0.5
        
        print("✓ Low confidence filtering test passed")
    
    def test_generate_description(self):
        """Test description generation"""
        desc = self.wrapper._generate_description(
            "WordPress",
            ["5.0"],
            {"X-Powered-By": "WordPress"},
            "wp-content"
        )
        
        assert "WordPress" in desc
        assert "5.0" in desc
        assert "HTTP headers" in desc
        print("✓ Description generation test passed")
    
    def test_generate_recommendation(self):
        """Test recommendation generation"""
        rec_wp = self.wrapper._generate_recommendation("WordPress")
        assert "WordPress" in rec_wp
        assert "updated" in rec_wp
        
        rec_nginx = self.wrapper._generate_recommendation("Nginx")
        assert "Nginx" in rec_nginx
        
        rec_unknown = self.wrapper._generate_recommendation("UnknownTech")
        assert "UnknownTech" in rec_unknown
        
        print("✓ Recommendation generation test passed")
    
    def test_extract_json_from_output(self):
        """Test JSON extraction from mixed output"""
        mixed_output = 'Some text {"plugins": {"WordPress": {}}} more text'
        
        result = self.wrapper._extract_json_from_output(mixed_output)
        
        assert result is not None
        assert "plugins" in result
        print("✓ JSON extraction test passed")
    
    def test_extract_json_invalid(self):
        """Test extraction with invalid JSON"""
        invalid_output = "No JSON here"
        
        result = self.wrapper._extract_json_from_output(invalid_output)
        
        assert result is None
        print("✓ Invalid JSON extraction test passed")
    
    @patch('subprocess.run')
    def test_run_successful(self, mock_run):
        """Test successful tool execution"""
        # Mock subprocess output
        mock_run.return_value = Mock(
            returncode=0,
            stdout=b'{"plugins": {"WordPress": {"versions": ["5.0"]}}}',
            stderr=b'',
            args=['whatweb', self.target]
        )
        
        result = self.wrapper.run(self.target)
        
        assert result.success is True
        assert len(result.findings) > 0
        assert result.tool_name == "whatweb"
        assert result.target == self.target
        print("✓ Successful run test passed")
    
    @patch('subprocess.run')
    def test_run_timeout(self, mock_run):
        """Test timeout handling"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('whatweb', 300)
        
        result = self.wrapper.run(self.target)
        
        assert result.success is False
        assert len(result.errors) > 0
        assert "timeout" in result.errors[0].lower()
        print("✓ Timeout handling test passed")
    
    @patch('subprocess.run')
    def test_run_exception(self, mock_run):
        """Test exception handling"""
        mock_run.side_effect = Exception("Connection refused")
        
        result = self.wrapper.run(self.target)
        
        assert result.success is False
        assert len(result.errors) > 0
        assert "execution failed" in result.errors[0].lower()
        print("✓ Exception handling test passed")
    
    @patch('subprocess.run')
    def test_run_with_options(self, mock_run):
        """Test run with options"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout=b'{"plugins": {}}',
            stderr=b'',
            args=['whatweb', self.target]
        )
        
        options = {
            "aggressive": True,
            "timeout": 60,
            "follow_redirects": True
        }
        
        result = self.wrapper.run(self.target, options)
        
        assert result.success is True
        # Verify command was called
        assert mock_run.called
        print("✓ Run with options test passed")
    
    def test_technology_severity_mapping(self):
        """Test technology severity mapping"""
        assert WhatWebWrapper.TECHNOLOGY_SEVERITY["WordPress"] == RiskLevel.INFO
        assert WhatWebWrapper.TECHNOLOGY_SEVERITY["Apache"] == RiskLevel.INFO
        assert WhatWebWrapper.TECHNOLOGY_SEVERITY["OpenSSL"] == RiskLevel.LOW
        print("✓ Technology severity mapping test passed")
    
    def test_confidence_multipliers(self):
        """Test confidence multiplier values"""
        multipliers = WhatWebWrapper.CONFIDENCE_MULTIPLIERS
        
        # High confidence sources
        assert multipliers["Meta-Generator"] >= 0.90
        assert multipliers["X-Powered-By"] >= 0.85
        
        # Lower confidence sources
        assert multipliers["Cookies"] <= 0.75
        assert multipliers["HTML"] <= 0.80
        
        print("✓ Confidence multipliers test passed")


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("WhatWeb Wrapper - Comprehensive Test Suite")
    print("=" * 70 + "\n")
    
    test_instance = TestWhatWebWrapper()
    test_instance.setup_method()
    
    tests = [
        test_instance.test_initialization,
        test_instance.test_build_command_basic,
        test_instance.test_build_command_with_options,
        test_instance.test_is_version,
        test_instance.test_calculate_confidence,
        test_instance.test_calculate_confidence_from_methods,
        test_instance.test_parse_text_line,
        test_instance.test_parse_text_line_invalid,
        test_instance.test_parse_text_output,
        test_instance.test_parse_json_output,
        test_instance.test_filter_low_confidence,
        test_instance.test_generate_description,
        test_instance.test_generate_recommendation,
        test_instance.test_extract_json_from_output,
        test_instance.test_extract_json_invalid,
        test_instance.test_run_successful,
        test_instance.test_run_timeout,
        test_instance.test_run_exception,
        test_instance.test_run_with_options,
        test_instance.test_technology_severity_mapping,
        test_instance.test_confidence_multipliers,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_func.__name__} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__} ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
