"""Showcase Mode - Safe demonstration mode for portfolio/demo"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from app.core.scanner import Finding, RiskLevel, VerificationStatus
from app.utils.logger import logger
import re
import random


class ShowcaseMode:
    """Showcase/Demo mode for safe data demonstration"""
    
    def __init__(self):
        self.logger = logger.bind(component="ShowcaseMode")
    
    DEMO_FINDINGS = [
        {
            "title": "SQL Injection in User ID Parameter",
            "description": "SQL injection vulnerability in user ID parameter allows database extraction",
            "risk_level": RiskLevel.CRITICAL,
            "affected_url": "/api/users",
            "evidence": {"parameter": "id", "injection_type": "time-based blind"},
            "recommendation": "Use parameterized queries",
            "confidence_score": 0.92,
            "sources": ["sqlmap", "manual"],
            "detection_method": "time_based_blind_injection",
        },
        {
            "title": "Reflected XSS in Search Function",
            "description": "User input in search parameter not properly sanitized",
            "risk_level": RiskLevel.HIGH,
            "affected_url": "/search",
            "evidence": {"parameter": "q", "payload_type": "img_onerror"},
            "recommendation": "Implement input validation and output encoding",
            "confidence_score": 0.88,
            "sources": ["xsstrike"],
            "detection_method": "reflected_xss",
        },
        {
            "title": "Missing HTTP Security Headers",
            "description": "Critical security headers missing from responses",
            "risk_level": RiskLevel.HIGH,
            "affected_url": "/",
            "evidence": {"missing_headers": ["CSP", "X-Frame-Options", "HSTS"]},
            "recommendation": "Add missing security headers",
            "confidence_score": 1.0,
            "sources": ["nikto"],
            "detection_method": "header_analysis",
        },
        {
            "title": "Weak SSL/TLS Configuration",
            "description": "Outdated SSL/TLS protocols or weak ciphers detected",
            "risk_level": RiskLevel.MEDIUM,
            "affected_url": "/",
            "evidence": {"protocol": "TLSv1.0", "weak_ciphers": ["RC4-SHA"]},
            "recommendation": "Upgrade to TLS 1.2 and remove weak ciphers",
            "confidence_score": 0.95,
            "sources": ["sslscan"],
            "detection_method": "ssl_scan",
        },
    ]
    
    def should_use_demo_mode(self, target_url: str) -> bool:
        """Check if demo mode should be used"""
        demo_domains = ["[DOMAIN-DEMO]", "demo-", "example.com", "localhost"]
        return any(d in target_url.lower() for d in demo_domains)
    
    def get_demo_findings(self, target_url: Optional[str] = None) -> List[Finding]:
        """Generate demo findings from templates"""
        base_url = self._normalize_demo_base_url(target_url)
        findings = []
        for template in self.DEMO_FINDINGS:
            finding = Finding(
                title=template["title"],
                description=template["description"],
                risk_level=template["risk_level"],
                affected_url=self._build_demo_url(base_url, template["affected_url"]),
                tool_name="demo",
                evidence=template["evidence"],
                recommendation=template["recommendation"],
                confidence_score=template["confidence_score"],
                sources=template["sources"],
                detection_method=template["detection_method"],
            )
            findings.append(finding)
        self.logger.info(f"Generated {len(findings)} demo findings")
        return findings

    def _normalize_demo_base_url(self, target_url: Optional[str]) -> str:
        if target_url:
            parsed = urlparse(target_url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        return "https://demo.example.com"

    def _build_demo_url(self, base_url: str, path: str) -> str:
        path_value = path if path.startswith("/") else f"/{path}"
        if path_value == "/":
            return base_url
        return f"{base_url.rstrip('/')}{path_value}"
    
    def mask_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data (domains, IPs, etc.)"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if isinstance(value, dict):
                    result[key] = self.mask_sensitive_data(value)
                elif isinstance(value, list):
                    result[key] = [self.mask_sensitive_data(item) if isinstance(item, (dict, list)) else self._mask_value(str(item)) for item in value]
                elif isinstance(value, str):
                    result[key] = self._mask_value(value)
                else:
                    result[key] = value
            return result
        elif isinstance(data, list):
            return [self.mask_sensitive_data(item) if isinstance(item, (dict, list)) else self._mask_value(str(item)) for item in data]
        else:
            return self._mask_value(str(data))
    
    def _mask_value(self, value: str) -> str:
        """Mask individual values"""
        # Mask domain names
        domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        value = re.sub(domain_pattern, 'https://[DOMAIN-DEMO].com', value)
        
        # Mask IP addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        value = re.sub(ip_pattern, '203.0.113.X', value)
        
        return value
    
    def stabilize_scan_duration(self, duration_seconds: float) -> float:
        """Stabilize scan duration to standard ranges"""
        if duration_seconds < 60:
            standard = 120  # 2 minutes
        elif duration_seconds < 300:
            standard = 300  # 5 minutes
        elif duration_seconds < 900:
            standard = 900  # 15 minutes
        else:
            standard = 1800  # 30 minutes
        
        # Add 5% variation
        variation = standard * 0.05 * random.uniform(-1, 1)
        return standard + variation
    
    def add_demo_watermark(self, output: Dict[str, Any]) -> Dict[str, Any]:
        """Add demo watermark to output"""
        output["_demo_mode_info"] = {
            "mode": "showcase",
            "watermark": "DEMO MODE - Data Sanitized",
            "data_masked": True,
        }
        return output
