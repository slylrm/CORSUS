"""
SQLMap Wrapper - SQL Injection Testing Tool - Enhanced
WAF detection, confidence scoring, cross-validation support
"""

from typing import Dict, List, Any, Optional
import json
import re
from datetime import datetime
from pathlib import Path

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.config import settings
from app.core.waf_detector import WAFDetector
from app.utils.logger import logger


class SQLMapWrapper(BaseToolWrapper):
    """
    SQLMap tool wrapper for SQL injection testing
    
    SQLMap, SQL injection açıklarını tespit etmek için kullanılan
    en popüler otomatik araçtır.
    
    Enhanced with:
    - WAF detection
    - Confidence scoring
    - Cross-validation support
    """
    
    name = "sqlmap"
    category = ToolCategory.INJECTION
    description = "Automatic SQL injection and database takeover tool"
    version = "1.8"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.sqlmap_path = config.get("path", settings.SQLMAP_PATH) if config else settings.SQLMAP_PATH
        self.waf_detector = WAFDetector()
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        SQLMap çalıştır (WAF detection ile)
        
        Args:
            target: Target URL (örn: https://example.com/page?id=1)
            options: {
                "level": 1-5 (test derinliği),
                "risk": 1-3 (risk seviyesi),
                "threads": 1-10,
                "technique": "BEUSTQ" (SQL injection teknikleri)
            }
        """
        start_time = datetime.now()
        options = options or {}
        
        # ✅ Detect WAF before running SQLMap
        logger.info(f"Detecting WAF for {target}")
        waf_detection = self.waf_detector.detect_waf(target)
        
        # If WAF is detected, adjust SQLMap parameters
        if waf_detection.detected:
            logger.info(f"WAF detected: {waf_detection.vendor} ({waf_detection.confidence_score:.0%})")
            # Reduce aggressiveness to avoid WAF blocking
            options["level"] = min(options.get("level", 1), 2)
            options["risk"] = min(options.get("risk", 1), 2)
        
        # Default options
        level = options.get("level", 1)
        risk = options.get("risk", 1)
        threads = options.get("threads", 1)
        technique = options.get("technique", "BEUST")  # Boolean, Error, Union, Stacked, Time-based
        
        # SQLMap command
        command = [
            self.sqlmap_path,
            "-u", target,
            "--level", str(level),
            "--risk", str(risk),
            "--threads", str(threads),
            "--technique", technique,
            "--batch",  # Non-interactive
            "--output-dir", str(settings.SQLMAP_OUTPUT_DIR),
            "--flush-session",  # Her scan için temiz başla
            "--answers", "quit=N",  # Otomatik cevaplar
            "--smart",  # Sadece error-based detection
        ]
        
        # JSON output için
        json_output_path = settings.SQLMAP_OUTPUT_DIR / f"scan_{datetime.now().timestamp()}.json"
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        
        findings = []
        errors = []
        raw_output = ""
        
        try:
            # Execute SQLMap
            result = self._execute_command(command, timeout=600)
            raw_output = result.stdout + result.stderr
            
            # Parse findings
            findings = self.parse_output(raw_output)
            
            # Validate each finding
            for finding in findings:
                finding.verified = self.validate_result(finding)

            if result.returncode != 0:
                error_detail = result.stderr.strip() or result.stdout.strip() or f"Exit code {result.returncode}"
                errors.append(error_detail[:500])
            
            success = result.returncode == 0 or len(findings) > 0
            
        except Exception as e:
            self.logger.error(f"SQLMap execution failed: {e}")
            errors.append(str(e))
            success = False
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=start_time,
            duration=duration,
            success=success,
            findings=[f.to_dict() for f in findings],
            raw_output=raw_output,
            errors=errors,
            metadata={
                "level": level,
                "risk": risk,
                "threads": threads,
                "technique": technique,
            }
        )
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        """
        SQLMap çıktısını parse et (confidence scoring ile)
        
        SQLMap output patterns:
        - "Parameter: id (GET) is vulnerable"
        - "Type: boolean-based blind"
        - "Title: AND boolean-based blind - WHERE or HAVING clause"
        """
        findings = []
        
        # SQL injection vulnerability pattern
        vuln_pattern = r"Parameter:\s+(\w+)\s+\((\w+)\)\s+.*?Type:\s+(.*?)\n.*?Title:\s+(.*?)\n"
        matches = re.finditer(vuln_pattern, raw_output, re.DOTALL)
        
        for match in matches:
            param_name = match.group(1)
            param_type = match.group(2)
            injection_type = match.group(3).strip()
            title = match.group(4).strip()
            
            # Risk seviyesi belirleme
            risk_level = self._determine_risk_level(injection_type)
            
            # ✅ Confidence scoring
            confidence = self._calculate_confidence(injection_type)
            
            # ✅ Detection method
            detection_method = self._get_detection_method(injection_type)
            
            # Finding oluştur
            finding = Finding(
                title=f"SQL Injection - {injection_type}",
                description=f"Parameter '{param_name}' ({param_type}) SQL injection açığına karşı savunmasızdır. "
                           f"Saldırgan, veritabanına yetkisiz erişim sağlayabilir, veri çalabilir veya değiştirebilir.",
                risk_level=risk_level,
                affected_url=f"Parameter: {param_name} ({param_type})",
                evidence={
                    "parameter": param_name,
                    "method": param_type,
                    "injection_type": injection_type,
                    "technique": title,
                    "raw_match": match.group(0)
                },
                recommendation=self._get_recommendation(injection_type),
                cwe_id="CWE-89",
                cvss_score=self._calculate_cvss(risk_level),
                confidence_score=confidence,
                sources=["sqlmap"],  # ✅ Source tracking
                detection_method=detection_method,  # ✅ Detection method
            )
            
            findings.append(finding)
        
        # Eğer "all tested parameters do not appear to be injectable" varsa
        if "all tested parameters do not appear to be injectable" in raw_output.lower():
            self.logger.info("No SQL injection vulnerabilities found")
        
        return findings
    
    def validate_result(self, finding: Finding) -> bool:
        """
        SQL injection bulgusunu doğrula
        
        Cross-validation için:
        1. Manuel payload test et
        2. Farklı bir tool ile doğrula (opsiyonel)
        """
        # Simple validation: Injection type kontrolü
        injection_type = finding.evidence.get("injection_type", "")
        
        # Time-based ve Boolean-based genelde daha güvenilirdir
        reliable_types = ["time-based blind", "boolean-based blind", "error-based"]
        
        if any(rt in injection_type.lower() for rt in reliable_types):
            return True
        
        # Union-based ve Stacked queries için ek validation gerekebilir
        return False  # Conservative approach
    
    def _determine_risk_level(self, injection_type: str) -> RiskLevel:
        """SQL injection tipine göre risk seviyesi belirle"""
        injection_type_lower = injection_type.lower()
        
        if "union" in injection_type_lower or "stacked" in injection_type_lower:
            return RiskLevel.CRITICAL
        elif "error" in injection_type_lower:
            return RiskLevel.HIGH
        elif "time" in injection_type_lower or "boolean" in injection_type_lower:
            return RiskLevel.HIGH
        else:
            return RiskLevel.MEDIUM
    
    def _calculate_cvss(self, risk_level: RiskLevel) -> float:
        """Risk seviyesine göre CVSS score hesapla"""
        cvss_map = {
            RiskLevel.CRITICAL: 9.8,
            RiskLevel.HIGH: 8.6,
            RiskLevel.MEDIUM: 6.5,
            RiskLevel.LOW: 4.0,
            RiskLevel.INFO: 0.0,
        }
        return cvss_map.get(risk_level, 5.0)
    
    def _get_recommendation(self, injection_type: str) -> str:
        """SQL injection için düzeltme önerisi"""
        return """
🔧 Nasıl Düzeltilir:
1. **Parametreli Sorgular (Prepared Statements) Kullanın:**
   ```python
   # ❌ Güvensiz
   query = f"SELECT * FROM users WHERE id = {user_id}"
   
   # ✅ Güvenli
   query = "SELECT * FROM users WHERE id = ?"
   cursor.execute(query, (user_id,))
   ```

2. **ORM Kullanın:**
   Django ORM, SQLAlchemy gibi ORM'ler otomatik olarak güvenlidir.

3. **Input Validation:**
   - Kullanıcı girdilerini her zaman validate edin
   - Whitelist yaklaşımı kullanın
   - Özel karakterleri filtreleyin

4. **Least Privilege Principle:**
   - Veritabanı kullanıcısına minimum yetki verin
   - SELECT-only kullanıcılar oluşturun

5. **Web Application Firewall (WAF):**
   - ModSecurity veya cloud-based WAF kullanın

📚 Kaynaklar:
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: Improper Neutralization of Special Elements
"""

    def _calculate_confidence(self, injection_type: str) -> float:
        """✅ SQL injection tipine göre confidence score hesapla"""
        injection_type_lower = injection_type.lower()
        
        # Time-based ve Boolean-based daha güvenilir
        if "time-based" in injection_type_lower or "boolean-based" in injection_type_lower:
            return 0.90  # 90% confidence
        elif "error-based" in injection_type_lower:
            return 0.88  # 88% confidence
        elif "union" in injection_type_lower:
            return 0.95  # 95% confidence (çok açık)
        elif "stacked" in injection_type_lower:
            return 0.92  # 92% confidence
        else:
            return 0.75  # Conservative for unknown types
    
    def _get_detection_method(self, injection_type: str) -> str:
        """✅ Detection method'unu döndür"""
        injection_type_lower = injection_type.lower()
        
        if "time-based" in injection_type_lower:
            return "time_based_blind_injection"
        elif "boolean-based" in injection_type_lower:
            return "boolean_based_blind_injection"
        elif "error-based" in injection_type_lower:
            return "error_based_injection"
        elif "union" in injection_type_lower:
            return "union_based_injection"
        elif "stacked" in injection_type_lower:
            return "stacked_query_injection"
        else:
            return "sql_injection_detection"


# Örnek kullanım
if __name__ == "__main__":
    wrapper = SQLMapWrapper()
    result = wrapper.run(
        target="http://testphp.vulnweb.com/artists.php?artist=1",
        options={"level": 1, "risk": 1}
    )
    print(json.dumps(result.to_dict(), indent=2))
