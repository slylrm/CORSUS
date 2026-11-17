"""
Example Tool Wrapper - Header Scanner
Demonstrating modular tool integration with ScannerEngine

Bu örnek, yeni tool'ların nasıl oluşturulacağını göstermektedir
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import requests
from app.config import settings
from urllib.parse import urlparse

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.utils.logger import logger


class HeaderScannerWrapper(BaseToolWrapper):
    """
    Basit bir Header Scanner tool wrapper'ı
    
    Web sitesinin HTTP başlıklarını tarar ve eksik güvenlik başlıklarını tespit eder
    
    Örnek: Security Headers Scanner
    """
    
    name = "header_scanner"
    category = ToolCategory.MISCONFIGURATION
    description = "Scans HTTP security headers"
    version = "1.0.0"
    requires_sudo = False
    
    # Kontrol edilmesi gereken kritik başlıklar
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "risk": RiskLevel.HIGH,
            "recommendation": "Enforce HSTS to prevent downgrade attacks"
        },
        "X-Content-Type-Options": {
            "risk": RiskLevel.MEDIUM,
            "recommendation": "Set to 'nosniff' to prevent MIME type sniffing"
        },
        "X-Frame-Options": {
            "risk": RiskLevel.MEDIUM,
            "recommendation": "Set to 'DENY' or 'SAMEORIGIN' to prevent clickjacking"
        },
        "Content-Security-Policy": {
            "risk": RiskLevel.HIGH,
            "recommendation": "Implement CSP to prevent XSS attacks"
        },
        "X-XSS-Protection": {
            "risk": RiskLevel.LOW,
            "recommendation": "Set to '1; mode=block' for browser-level protection"
        }
    }
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        HTTP başlıklarını tarar
        
        Args:
            target: Target URL (örn: https://example.com)
            options: Tool-specific options
            
        Returns:
            ToolResult with findings
        """
        start_time = datetime.now()
        
        try:
            # Target'tan başlıkları al
            headers = self._fetch_headers(target)
            
            # Eksik güvenlik başlıklarını tespit et
            findings_data = self._analyze_headers(headers, target)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return ToolResult(
                tool_name=self.name,
                category=self.category.value,
                target=target,
                timestamp=start_time,
                duration=duration,
                success=True,
                findings=findings_data,
                raw_output=str(headers),
                errors=[],
                metadata={"headers_checked": len(headers)}
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return ToolResult(
                tool_name=self.name,
                category=self.category.value,
                target=target,
                timestamp=start_time,
                duration=duration,
                success=False,
                findings=[],
                raw_output="",
                errors=[str(e)],
            )
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        """
        Tool çıktısını parse et
        (Bu örneğin run() metodunda doğrudan findings döndürüldüğü için
        bu method çoğu zaman boş kalır)
        """
        return []
    
    def _fetch_headers(self, target: str) -> Dict[str, str]:
        """
        Target'tan HTTP başlıklarını al
        """
        try:
            response = requests.head(
                target,
                timeout=10,
                verify=settings.HTTP_VERIFY_TLS,
                allow_redirects=True
            )
            return dict(response.headers)
        except Exception as e:
            logger.error(f"Error fetching headers from {target}: {e}")
            raise
    
    def _analyze_headers(self, headers: Dict[str, str], target: str) -> List[Dict]:
        """
        HTTP başlıklarını analiz et ve eksikleri tespit et
        """
        findings = []
        found_headers = set(headers.keys())
        
        # Eksik başlıkları kontrol et
        for header_name, info in self.SECURITY_HEADERS.items():
            if header_name not in found_headers:
                findings.append({
                    "title": f"Missing Security Header: {header_name}",
                    "description": f"The {header_name} header is not present in the response.",
                    "risk_level": info["risk"].value,
                    "affected_url": target,
                    "evidence": {"missing_header": header_name},
                    "recommendation": info["recommendation"],
                    "confidence_score": 1.0,
                })
        
        # Mevcut başlıkları kontrol et
        hsts_header = headers.get("Strict-Transport-Security", "")
        if hsts_header and "max-age" not in hsts_header.lower():
            findings.append({
                "title": "Weak HSTS Configuration",
                "description": "HSTS header is present but may be weak.",
                "risk_level": RiskLevel.MEDIUM.value,
                "affected_url": target,
                "evidence": {"hsts_value": hsts_header},
                "recommendation": "Ensure max-age is set to at least 31536000",
                "confidence_score": 0.7,
            })
        
        # Server başlığı disclosure
        server_header = headers.get("Server", "")
        if server_header:
            findings.append({
                "title": "Server Banner Disclosure",
                "description": f"Server version is disclosed: {server_header}",
                "risk_level": RiskLevel.LOW.value,
                "affected_url": target,
                "evidence": {"server": server_header},
                "recommendation": "Configure server to hide version information",
                "confidence_score": 0.95,
                "cwe_id": "CWE-200",
            })
        
        return findings


# Kullanım Örneği - API'ye Ekleme
"""
# backend/app/api/scans.py içinde:

from app.tools.examples.header_scanner import HeaderScannerWrapper

# run_scan_task() fonksiyonu içinde:
tool_classes = {
    "nmap": NmapWrapper,
    "sqlmap": SQLMapWrapper,
    "header_scanner": HeaderScannerWrapper,  # Yeni tool!
}

# Scan isteğinde kullan:
{
    "target_url": "https://example.com",
    "scan_type": "quick",
    "tools": ["header_scanner"]
}
"""
