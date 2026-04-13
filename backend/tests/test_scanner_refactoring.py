"""
ScannerEngine Refactoring Tests
Tool orchestration, error handling, and integration tests
"""

import asyncio
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, AsyncMock, MagicMock, patch

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False

# Imports (varsayılan)
from app.core.scanner import (
    ScannerEngine, Scan, Finding, ScanStatus, VerificationStatus, ToolRunner
)
from app.tools.base import BaseToolWrapper, ToolResult, RiskLevel, ToolCategory


class MockToolWrapper(BaseToolWrapper):
    """Mock tool for testing"""
    name = "mock_tool"
    category = ToolCategory.DISCOVERY
    description = "Mock tool for testing"
    
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = None
    
    def run(self, target: str, options=None) -> ToolResult:
        """Simulate tool execution"""
        return ToolResult(
            tool_name="mock_tool",
            category="discovery",
            target=target,
            timestamp=__import__('datetime').datetime.now(),
            duration=1.5,
            success=True,
            findings=[
                {
                    "title": "Test Finding",
                    "description": "Test description",
                    "risk_level": "medium",
                    "affected_url": target,
                    "evidence": {"test": True},
                    "recommendation": "Test recommendation",
                    "confidence_score": 0.85,
                }
            ],
            raw_output="Mock output",
            errors=[],
            metadata={},
        )
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        return []


class FailingToolWrapper(BaseToolWrapper):
    """Tool that fails for testing error handling"""
    name = "failing_tool"
    category = ToolCategory.DISCOVERY
    
    def run(self, target: str, options=None) -> ToolResult:
        raise RuntimeError("Tool intentionally failed")
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        return []


class SlowToolWrapper(BaseToolWrapper):
    """Slow tool for testing timeout"""
    name = "slow_tool"
    category = ToolCategory.DISCOVERY

    def __init__(self, config=None):
        self.config = config or {}
        self.logger = None
    
    def run(self, target: str, options=None) -> ToolResult:
        import time
        time.sleep(10)  # Simulate long execution
        return ToolResult(
            tool_name="slow_tool",
            category="discovery",
            target=target,
            timestamp=__import__('datetime').datetime.now(),
            duration=10.0,
            success=True,
            findings=[],
            raw_output="",
            errors=[],
        )
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        return []


class TestScannerEngine:
    """ScannerEngine unit tests"""
    
    def test_create_scan(self):
        """Test scan creation"""
        engine = ScannerEngine()
        scan = engine.create_scan(
            target_url="https://example.com",
            scan_type="quick",
            tools=["tool1", "tool2"]
        )
        
        assert scan is not None
        assert scan.target_url == "https://example.com"
        assert scan.scan_type == "quick"
        assert scan.status == ScanStatus.PENDING
        assert len(scan.tools) == 2
    
    def test_get_scan(self):
        """Test retrieving scan"""
        engine = ScannerEngine()
        scan = engine.create_scan("https://example.com", "quick")
        
        retrieved = engine.get_scan(scan.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == scan.scan_id
    
    def test_get_scan_not_found(self):
        """Test getting non-existent scan"""
        engine = ScannerEngine()
        result = engine.get_scan("non-existent-id")
        assert result is None
    
    def test_scan_to_dict(self):
        """Test scan serialization"""
        engine = ScannerEngine()
        scan = engine.create_scan("https://example.com", "quick")
        
        scan_dict = scan.to_dict()
        assert scan_dict["scan_id"] == scan.scan_id
        assert scan_dict["target_url"] == "https://example.com"
        assert scan_dict["status"] == "pending"


class TestToolRunner:
    """ToolRunner unit tests"""
    
    @pytest.mark.asyncio
    async def test_run_successful_tool(self):
        """Test successful tool execution"""
        runner = ToolRunner(timeout=10)
        success, findings, error = await runner.run_tool(
            MockToolWrapper,
            "https://example.com"
        )
        
        assert success is True
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"
        assert error is None
    
    @pytest.mark.asyncio
    async def test_run_tool_timeout(self):
        """Test tool timeout handling"""
        runner = ToolRunner(timeout=1)
        success, findings, error = await runner.run_tool(
            SlowToolWrapper,
            "https://example.com"
        )
        
        assert success is False
        assert len(findings) == 0
        assert "timeout" in error.lower()
    
    @pytest.mark.asyncio
    async def test_run_tool_exception(self):
        """Test tool exception handling"""
        runner = ToolRunner(timeout=10)
        success, findings, error = await runner.run_tool(
            FailingToolWrapper,
            "https://example.com"
        )
        
        assert success is False
        assert len(findings) == 0
        assert error is not None
    
    def test_convert_to_findings(self):
        """Test ToolResult to Finding conversion"""
        runner = ToolRunner()
        
        tool_result = ToolResult(
            tool_name="test_tool",
            category="discovery",
            target="https://example.com",
            timestamp=__import__('datetime').datetime.now(),
            duration=1.5,
            success=True,
            findings=[
                {
                    "title": "Test Finding 1",
                    "description": "Description 1",
                    "risk_level": "high",
                    "affected_url": "https://example.com/test",
                    "evidence": {},
                    "recommendation": "Fix this",
                    "confidence_score": 0.9,
                }
            ],
            raw_output="",
            errors=[],
        )
        
        findings = runner._convert_to_findings(tool_result)
        
        assert len(findings) == 1
        assert findings[0].title == "Test Finding 1"
        assert findings[0].tool_name == "test_tool"
        assert findings[0].risk_level == RiskLevel.HIGH


class TestFinding:
    """Finding model tests"""
    
    def test_finding_creation(self):
        """Test finding creation"""
        finding = Finding(
            title="Test Vulnerability",
            description="This is a test",
            risk_level=RiskLevel.CRITICAL,
            affected_url="https://example.com",
            tool_name="test_tool",
            confidence_score=0.95,
            cwe_id="CWE-89"
        )
        
        assert finding.title == "Test Vulnerability"
        assert finding.risk_level == RiskLevel.CRITICAL
        assert finding.confidence_score == 0.95
        assert finding.verification_status == VerificationStatus.UNVERIFIED
    
    def test_finding_to_dict(self):
        """Test finding serialization"""
        finding = Finding(
            title="Test",
            description="Test",
            risk_level=RiskLevel.HIGH,
            affected_url="https://example.com",
            tool_name="test",
        )
        
        finding_dict = finding.to_dict()
        assert finding_dict["title"] == "Test"
        assert finding_dict["risk_level"] == "high"
        assert "id" in finding_dict
        assert "found_at" in finding_dict


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow"""
        engine = ScannerEngine()
        
        # Create scan
        scan = engine.create_scan(
            target_url="https://example.com",
            scan_type="quick",
            tools=["mock_tool"]
        )
        
        # Run scan
        tool_classes = {
            "mock_tool": MockToolWrapper,
        }
        
        await engine.run_scan(scan.scan_id, tool_classes)
        
        # Verify scan completed
        updated_scan = engine.get_scan(scan.scan_id)
        assert updated_scan.status == ScanStatus.COMPLETED
        assert len(updated_scan.findings) > 0
    
    @pytest.mark.asyncio
    async def test_scan_with_multiple_tools(self):
        """Test scan with multiple tools"""
        engine = ScannerEngine()
        
        scan = engine.create_scan(
            target_url="https://example.com",
            scan_type="standard",
            tools=["mock_tool", "mock_tool"]
        )
        
        tool_classes = {
            "mock_tool": MockToolWrapper,
        }
        
        await engine.run_scan(scan.scan_id, tool_classes)
        
        updated_scan = engine.get_scan(scan.scan_id)
        assert updated_scan.status == ScanStatus.COMPLETED
        # Duplicate findings are merged into a single risk story by the scanner.
        assert len(updated_scan.findings) >= 1
    
    @pytest.mark.asyncio
    async def test_scan_with_tool_failure(self):
        """Test scan continues when tool fails"""
        engine = ScannerEngine()
        
        scan = engine.create_scan(
            target_url="https://example.com",
            scan_type="quick",
            tools=["failing_tool", "mock_tool"]
        )
        
        tool_classes = {
            "failing_tool": FailingToolWrapper,
            "mock_tool": MockToolWrapper,
        }
        
        await engine.run_scan(scan.scan_id, tool_classes)
        
        updated_scan = engine.get_scan(scan.scan_id)
        assert updated_scan.status == ScanStatus.COMPLETED
        # Should have errors recorded
        assert "failing_tool" in updated_scan.tool_errors
        # But mock_tool should still have added findings
        assert len(updated_scan.findings) > 0


class TestErrorHandling:
    """Error handling tests"""
    
    @pytest.mark.asyncio
    async def test_missing_tool_class(self):
        """Test handling of missing tool class"""
        engine = ScannerEngine()
        
        scan = engine.create_scan(
            target_url="https://example.com",
            scan_type="quick",
            tools=["nonexistent_tool"]
        )
        
        await engine.run_scan(scan.scan_id, {})
        
        updated_scan = engine.get_scan(scan.scan_id)
        assert updated_scan.status == ScanStatus.COMPLETED
        assert "nonexistent_tool" in updated_scan.tool_errors
    
    def test_finding_with_string_risk_level(self):
        """Test finding accepts string risk level"""
        finding = Finding(
            title="Test",
            description="Test",
            risk_level="critical",  # String
            affected_url="https://example.com",
            tool_name="test",
        )
        
        assert finding.risk_level == RiskLevel.CRITICAL


# Çalıştırma: pytest backend/tests/test_scanner_refactoring.py -v
