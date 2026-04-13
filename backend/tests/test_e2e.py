"""
End-to-End Testing Suite for WeppenTest
Tests all 7 implementation categories
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.append(str(Path(__file__).resolve().parents[2]))

from app.core.scanner import Finding, RiskLevel, VerificationStatus
from app.core.cross_validator import CrossValidator
from app.core.waf_detector import WAFDetector
from app.core.result_validator import ResultValidator
from app.core.showcase_mode import ShowcaseMode
from app.utils.logger import logger


class E2ETestSuite:
    """End-to-end testing suite"""
    
    def __init__(self):
        self.cross_validator = CrossValidator()
        self.waf_detector = WAFDetector()
        self.result_validator = ResultValidator()
        self.showcase_mode = ShowcaseMode()
        self.test_results = []
    
    # ============================================================
    # TEST 1️⃣: FALSE POSITIVE KONTROLÜ
    # ============================================================
    
    def test_false_positive_control(self):
        """Test false positive kontrol mekanizması"""
        logger.info("=" * 60)
        logger.info("TEST 1️⃣: FALSE POSITIVE KONTROLÜ")
        logger.info("=" * 60)
        
        # Scenario: Tek tool'dan gelen CRITICAL finding
        finding = Finding(
            title="SQL Injection in 'id' parameter",
            description="SQL injection vulnerability detected",
            risk_level=RiskLevel.CRITICAL,
            affected_url="https://example.com/api/users?id=1",
            tool_name="sqlmap",
            evidence={"payload": "' OR '1'='1"},
            recommendation="Use parameterized queries",
            confidence_score=0.85,
            sources=["sqlmap"],  # Tek tool
        )
        
        # Validate
        validated = self.result_validator.validate_findings([finding])
        
        # Check: Tek tool'dan CRITICAL olamaz
        if validated[0].risk_level == RiskLevel.HIGH:
            logger.info("✅ PASS: Single-tool finding correctly downgraded to HIGH")
            self.test_results.append(("FALSE_POSITIVE_CONTROL", "PASS"))
        else:
            logger.error(f"❌ FAIL: Expected HIGH, got {validated[0].risk_level}")
            self.test_results.append(("FALSE_POSITIVE_CONTROL", "FAIL"))
    
    # ============================================================
    # TEST 2️⃣: TOOL CROSS-VALIDATION
    # ============================================================
    
    def test_cross_validation(self):
        """Test cross-validation mekanizması"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 2️⃣: TOOL CROSS-VALIDATION")
        logger.info("=" * 60)
        
        # Scenario: Aynı bulgu 2 tool'dan geldi
        finding1 = Finding(
            title="SQL Injection",
            description="SQL injection",
            risk_level=RiskLevel.CRITICAL,
            affected_url="https://example.com/api/users?id=1",
            tool_name="sqlmap",
            evidence={"payload": "' OR '1'='1"},
            recommendation="Use parameterized queries",
            confidence_score=0.85,
            sources=["sqlmap"],
        )
        
        finding2 = Finding(
            title="SQL Injection",
            description="SQL injection",
            risk_level=RiskLevel.CRITICAL,
            affected_url="https://example.com/api/users?id=1",
            tool_name="nikto",
            evidence={"payload": "' OR '1'='1"},
            recommendation="Use parameterized queries",
            confidence_score=0.80,
            sources=["nikto"],
        )
        
        # Cross-validate
        merged = self.cross_validator.cross_validate_findings([finding1, finding2])
        
        # Check: 2 tool'dan gelirseConfidence artar ve VERIFIED olur
        if len(merged) == 1 and merged[0].verification_status == VerificationStatus.VERIFIED:
            logger.info(f"✅ PASS: Merged findings (confidence: {merged[0].confidence_score:.0%})")
            self.test_results.append(("CROSS_VALIDATION", "PASS"))
        else:
            logger.error("❌ FAIL: Cross-validation failed")
            self.test_results.append(("CROSS_VALIDATION", "FAIL"))
    
    # ============================================================
    # TEST 3️⃣: WAF DETECTION
    # ============================================================
    
    async def test_waf_detection(self):
        """Test WAF detection mekanizması"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 3️⃣: WAF DETECTION")
        logger.info("=" * 60)
        
        # Test URL (demo domain)
        target_url = "https://example.com"
        
        # Passive WAF detection
        waf_result = self.waf_detector.detect_waf(target_url)
        
        logger.info(f"WAF Detection Result:")
        logger.info(f"  Detected: {waf_result.detected}")
        logger.info(f"  Vendor: {waf_result.vendor}")
        logger.info(f"  Confidence: {waf_result.confidence_score:.0%}")
        logger.info(f"  Method: {waf_result.detection_method}")
        
        # Check: WAF detection işe yarıyor mu
        if isinstance(waf_result.detected, bool):
            logger.info("✅ PASS: WAF detection completed")
            self.test_results.append(("WAF_DETECTION", "PASS"))
        else:
            logger.error("❌ FAIL: WAF detection failed")
            self.test_results.append(("WAF_DETECTION", "FAIL"))
    
    # ============================================================
    # TEST 4️⃣: CONFIDENCE SCORING
    # ============================================================
    
    def test_confidence_scoring(self):
        """Test confidence scoring mekanizması"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 4️⃣: CONFIDENCE SCORING")
        logger.info("=" * 60)
        
        # Scenario: Farklı confidence'lı findings
        findings = [
            Finding(
                title="High-confidence finding",
                description="Multiple tools confirmed",
                risk_level=RiskLevel.HIGH,
                affected_url="https://example.com/api/1",
                tool_name="sqlmap",
                evidence={"type": "union_based"},
                recommendation="Fix SQL injection",
                confidence_score=0.95,
                sources=["sqlmap", "manual"],
            ),
            Finding(
                title="Low-confidence finding",
                description="Single heuristic detection",
                risk_level=RiskLevel.MEDIUM,
                affected_url="https://example.com/api/2",
                tool_name="nikto",
                evidence={"type": "pattern_match"},
                recommendation="Verify manually",
                confidence_score=0.60,
                sources=["nikto"],
            ),
        ]
        
        # Validate
        validated = self.result_validator.validate_findings(findings)
        
        # Check: Confidence scores are properly assigned
        if (validated[0].confidence_score > 0.85 and 
            validated[1].verification_status == VerificationStatus.NEEDS_MANUAL):
            logger.info(f"✅ PASS: Confidence scoring correct")
            logger.info(f"  Finding 1: {validated[0].confidence_score:.0%}")
            logger.info(f"  Finding 2: {validated[1].confidence_score:.0%}")
            self.test_results.append(("CONFIDENCE_SCORING", "PASS"))
        else:
            logger.error("❌ FAIL: Confidence scoring incorrect")
            self.test_results.append(("CONFIDENCE_SCORING", "FAIL"))
    
    # ============================================================
    # TEST 5️⃣: SHOWCASE MODE
    # ============================================================
    
    def test_showcase_mode(self):
        """Test showcase mode masking"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 5️⃣: SHOWCASE MODE")
        logger.info("=" * 60)
        
        # Test data
        data = {
            "target_url": "https://real-domain-name.com/api/users",
            "ip": "192.168.1.100",
            "findings": [
                {
                    "affected_url": "https://real-domain-name.com/api/users?id=1",
                    "evidence": {"payload": "192.168.1.50 injected"}
                }
            ]
        }
        
        # Mask
        masked = self.showcase_mode.mask_sensitive_data(data)
        
        # Check: Sensitive data is masked
        if ("[DOMAIN-DEMO]" in masked["target_url"] and 
            "192.168.1" not in str(masked)):
            logger.info("✅ PASS: Showcase mode masking works")
            logger.info(f"  Original URL: {data['target_url']}")
            logger.info(f"  Masked URL: {masked['target_url']}")
            self.test_results.append(("SHOWCASE_MODE", "PASS"))
        else:
            logger.error("❌ FAIL: Showcase mode masking failed")
            self.test_results.append(("SHOWCASE_MODE", "FAIL"))
    
    # ============================================================
    # TEST 6️⃣: DEMO FINDINGS
    # ============================================================
    
    def test_demo_findings(self):
        """Test demo findings generation"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 6️⃣: DEMO FINDINGS")
        logger.info("=" * 60)
        
        # Get demo findings
        demo_findings = self.showcase_mode.get_demo_findings()
        
        # Check
        if len(demo_findings) > 0 and all(isinstance(f, Finding) for f in demo_findings):
            logger.info(f"✅ PASS: Generated {len(demo_findings)} demo findings")
            for i, f in enumerate(demo_findings[:3], 1):
                logger.info(f"  {i}. {f.title} ({f.risk_level.value})")
            self.test_results.append(("DEMO_FINDINGS", "PASS"))
        else:
            logger.error("❌ FAIL: Demo findings generation failed")
            self.test_results.append(("DEMO_FINDINGS", "FAIL"))
    
    # ============================================================
    # TEST 7️⃣: VERIFICATION STATUS FLOW
    # ============================================================
    
    def test_verification_status_flow(self):
        """Test verification status transitions"""
        logger.info("\n" + "=" * 60)
        logger.info("TEST 7️⃣: VERIFICATION STATUS FLOW")
        logger.info("=" * 60)
        
        # Scenario: Finding verification status changes
        finding = Finding(
            title="Test Finding",
            description="Test",
            risk_level=RiskLevel.HIGH,
            affected_url="https://example.com",
            tool_name="test",
            evidence={},
            recommendation="Test",
            confidence_score=0.70,
            sources=["test"],
        )
        
        # Initial state
        assert finding.verification_status == VerificationStatus.UNVERIFIED
        logger.info(f"  Initial: {finding.verification_status.value}")
        
        # After validation
        validated = self.result_validator.validate_findings([finding])
        assert validated[0].verification_status == VerificationStatus.NEEDS_MANUAL
        logger.info(f"  After validation: {validated[0].verification_status.value}")
        
        # Check
        logger.info("✅ PASS: Verification status flow correct")
        self.test_results.append(("VERIFICATION_STATUS", "PASS"))
    
    # ============================================================
    # REPORT
    # ============================================================
    
    def run_all_tests(self):
        """Run all E2E tests"""
        logger.info("\n" + "🚀" * 30)
        logger.info("🚀 END-TO-END TEST SUITE 🚀".center(60))
        logger.info("🚀" * 30)
        
        # Run all tests
        self.test_false_positive_control()
        self.test_cross_validation()
        asyncio.run(self.test_waf_detection())
        self.test_confidence_scoring()
        self.test_showcase_mode()
        self.test_demo_findings()
        self.test_verification_status_flow()
        
        # Report
        self._print_report()
    
    def _print_report(self):
        """Print test results report"""
        logger.info("\n" + "=" * 60)
        logger.info("📊 TEST RESULTS REPORT")
        logger.info("=" * 60)
        
        passed = sum(1 for _, status in self.test_results if status == "PASS")
        total = len(self.test_results)
        
        for test_name, status in self.test_results:
            icon = "✅" if status == "PASS" else "❌"
            logger.info(f"{icon} {test_name}: {status}")
        
        logger.info("=" * 60)
        logger.info(f"📈 TOTAL: {passed}/{total} tests passed ({passed*100//total}%)")
        logger.info("=" * 60)
        
        if passed == total:
            logger.info("🎉 ALL TESTS PASSED! 🎉")
        else:
            logger.warning(f"⚠️  {total - passed} tests failed")


# Run tests
if __name__ == "__main__":
    suite = E2ETestSuite()
    suite.run_all_tests()
