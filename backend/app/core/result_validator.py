"""
Result Validator - Enhanced
Bulguları doğrular ve false positive kontrolü yapar
False positive azaltmak için confidence scoring ve multi-tool validation
"""
from typing import List, Dict, Any, Tuple, Optional
from app.core.scanner import Finding, RiskLevel, VerificationStatus
from app.utils.logger import logger
import re


class ResultValidator:
    """
    Tarama sonuçlarını doğrulayan sınıf
    
    - False positive detection
    - Confidence scoring
    - Multi-tool validation enforcement
    - WAF impact on confidence
    """
    
    def __init__(self):
        self.logger = logger.bind(component="ResultValidator")
        
        # Tool confidence scores (each tool's reliability)
        self.tool_confidence = {
            "nmap": 0.98,           # Port scanning = very reliable
            "sqlmap": 0.90,         # SQL injection = reliable but WAF issues
            "nikto": 0.75,          # Web scanner = heuristic based
            "xsstrike": 0.70,       # XSS detection = often heuristic
            "dalfox": 0.72,         # XSS detection = heuristic
            "wpscan": 0.85,         # WordPress = signature based
            "cmsmap": 0.78,         # CMS detection = medium reliability
            "subjack": 0.82,        # Subdomain takeover = reliable
            "dnsdumpster": 0.80,    # DNS enumeration = reliable
            "sslscan": 0.95,        # SSL/TLS = very reliable
        }
        
        # Known false positive patterns
        self.false_positive_patterns = {
            "sql_injection": [
                r"error\s+in\s+your\s+SQL\s+syntax",
                r"mysql_fetch",
                r"ORA-\d+",
                r"SQLSTATE",
                r"SQLException",
            ],
            "xss": [
                r"<script>alert\(['\"]xss['\"]\)</script>",
                r"reflected.*payload",
            ],
        }
    
    def validate_findings(
        self, 
        findings: List[Finding], 
        waf_detected: bool = False,
        require_multiple_evidence: bool = True
    ) -> List[Finding]:
        """
        Bulguları doğrula ve confidence scoring uygula
        
        Args:
            findings: Bulgular listesi
            waf_detected: WAF tespit edildi mi? (confidence'i etkiler)
            require_multiple_evidence: En az 2 kanıt gerektir mi?
            
        Returns:
            Doğrulanmış bulgular (confidence_score + verification_status ile)
        """
        
        validated = []
        
        for finding in findings:
            is_valid, confidence = self._validate_single_finding(finding, waf_detected)
            
            # Confidence score'ı set et
            finding.confidence_score = confidence
            
            # Verification status'ü belirle
            if is_valid and confidence > 0.85:
                finding.verification_status = VerificationStatus.VERIFIED
            elif is_valid and confidence > 0.65:
                finding.verification_status = VerificationStatus.NEEDS_MANUAL
            else:
                finding.verification_status = VerificationStatus.UNVERIFIED
            
            # Severity kurallarını uygula
            finding = self._enforce_severity_rules(finding)
            
            validated.append(finding)
            
            self.logger.info(
                f"Validated: {finding.title} | "
                f"Confidence: {finding.confidence_score:.0%} | "
                f"Status: {finding.verification_status.value} | "
                f"Risk: {finding.risk_level.value}"
            )
        
        return validated
    
    def _validate_single_finding(self, finding: Finding, waf_detected: bool = False) -> Tuple[bool, float]:
        """
        Tek bir bulguyu doğrula ve confidence score ver
        
        Returns:
            (is_valid, confidence_score: 0.0 - 1.0)
        """
        
        confidence = 1.0
        
        # 1. Evidence check
        if not finding.evidence or len(finding.evidence) == 0:
            self.logger.warning(f"No evidence for finding: {finding.title}")
            return False, 0.0
        
        # 2. False positive pattern check
        if self._is_known_false_positive(finding):
            self.logger.warning(f"Known false positive detected: {finding.title}")
            return False, 0.0
        
        # 3. Tool confidence
        tool_name = finding.tool_name or finding.sources[0] if finding.sources else "unknown"
        tool_base_confidence = self.tool_confidence.get(tool_name.lower(), 0.75)
        confidence *= tool_base_confidence
        
        # 4. Evidence quality check
        has_request_response = ("request" in finding.evidence or "response" in finding.evidence)
        has_payload = "payload" in finding.evidence
        has_exploitation_proof = ("status_code" in finding.evidence or "response_diff" in finding.evidence)
        
        # Critical/High severity bulguların mutlaka evidence'ı olmalı
        if finding.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            if not (has_payload or has_exploitation_proof):
                confidence *= 0.7
                finding.low_confidence_reason = "No exploitation proof for critical finding"
        
        # 5. WAF impact
        if waf_detected:
            confidence *= 0.75  # WAF varsa %25 düşür
            finding.low_confidence_reason = (finding.low_confidence_reason or "") + " (WAF detected - may block exploitation)"
        
        # 6. Tool count factor
        tool_count = len(finding.sources or [1])
        if tool_count == 1:
            confidence *= 0.9  # Tek tool penalty
        elif tool_count >= 2:
            confidence *= 1.05  # Multi-tool bonus (cap at 1.0)
        
        confidence = min(confidence, 1.0)
        confidence = max(confidence, 0.0)
        
        return confidence > 0.5, confidence
    
    def _is_known_false_positive(self, finding: Finding) -> bool:
        """Bilinen false positive pattern'lerini kontrol et"""
        
        try:
            title = finding.title.lower()
            evidence = str(finding.evidence).lower()
            
            # SQL Injection false positive patterns
            if "sql" in title:
                for pattern in self.false_positive_patterns["sql_injection"]:
                    if re.search(pattern, evidence, re.IGNORECASE):
                        return True
            
            # XSS false positive patterns
            if "xss" in title or "cross-site" in title:
                for pattern in self.false_positive_patterns["xss"]:
                    if re.search(pattern, evidence, re.IGNORECASE):
                        return True
            
            return False
        
        except Exception as e:
            self.logger.debug(f"False positive check error: {e}")
            return False
    
    def _enforce_severity_rules(self, finding: Finding) -> Finding:
        """
        Severity kurallarını uygula:
        - Tek tool'dan geliyorsa CRITICAL olamaz
        - Confidence düşükse severity düşür
        """
        
        tool_count = len(finding.sources or [1])
        
        # Kural 1: Tek tool'dan CRITICAL olamaz
        if tool_count == 1 and finding.risk_level == RiskLevel.CRITICAL:
            finding.risk_level = RiskLevel.HIGH
            finding.low_confidence_reason = "Single tool detection - cannot be critical"
            self.logger.info(f"Downgraded to HIGH: {finding.title} (single tool)")
        
        # Kural 2: Low confidence'ın severity'si MEDIUM max
        if finding.confidence_score < 0.65 and finding.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            finding.risk_level = RiskLevel.MEDIUM
            self.logger.info(f"Downgraded to MEDIUM: {finding.title} (low confidence)")
        
        # Kural 3: Very low confidence = INFO level
        if finding.confidence_score < 0.50:
            finding.risk_level = RiskLevel.INFO
            finding.is_low_confidence = True
        
        return finding
        
        # 1. Evidence kontrolü
        if not finding.evidence or len(finding.evidence) == 0:
            self.logger.debug(f"No evidence for: {finding.title}")
            return False, 0.0
        
        # 2. Known false positive kontrolü
        if self._is_known_false_positive(finding):
            self.logger.debug(f"Known false positive: {finding.title}")
            return False, 0.0
        
        # 3. Risk seviyesi kontrolü
        if finding.risk_level == RiskLevel.INFO:
            confidence *= 0.8
        
        # 4. Tool güvenilirliği
        confidence *= self._get_tool_confidence(finding.evidence.get("tool_name", ""))
        
        # 5. Minimum confidence threshold
        if confidence < 0.6:
            return False, confidence
        
        return True, confidence
    
    def _is_known_false_positive(self, finding: Finding) -> bool:
        """Bilinen false positive pattern'leri kontrol et"""
        
        title_lower = finding.title.lower()
        description_lower = finding.description.lower()
        
        # SQL Injection false positives
        if "sql" in title_lower:
            evidence_str = str(finding.evidence).lower()
            for pattern in self.false_positive_patterns["sql_injection"]:
                if re.search(pattern, evidence_str, re.IGNORECASE):
                    # Ek kontrol: Gerçekten SQL hatası mı?
                    if "sleep" in evidence_str or "benchmark" in evidence_str:
                        return False  # Time-based, güvenilir
                    return True
        
        # XSS false positives
        if "xss" in title_lower:
            evidence_str = str(finding.evidence).lower()
            for pattern in self.false_positive_patterns["xss"]:
                if re.search(pattern, evidence_str, re.IGNORECASE):
                    return True
        
        return False
    
    def _get_tool_confidence(self, tool_name: str) -> float:
        """
        Tool'a göre güven skoru
        
        Bazı tool'lar daha güvenilirdir
        """
        
        tool_confidence = {
            "sqlmap": 0.95,      # Çok güvenilir
            "nmap": 0.98,        # Port scanning kesin
            "nikto": 0.75,       # Bazen false positive
            "xsstrike": 0.70,    # XSS detection zor
            "dalfox": 0.80,
            "wpscan": 0.85,
        }
        
        return tool_confidence.get(tool_name.lower(), 0.8)
    
    def cross_validate(
        self,
        finding: Finding,
        alternative_tool: str
    ) -> bool:
        """
        Başka bir tool ile cross-validate et
        
        Args:
            finding: Doğrulanacak bulgu
            alternative_tool: Alternatif tool adı
            
        Returns:
            Doğrulandı mı?
        """
        
        # TODO: Alternatif tool ile yeniden test et
        self.logger.info(
            f"Cross-validating {finding.title} with {alternative_tool}"
        )
        
        return True
    
    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Duplicate bulguları temizle
        
        Aynı URL ve aynı açık tipi için sadece bir bulgu tut
        """
        
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (
                finding.title,
                finding.affected_url,
                finding.risk_level
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                self.logger.debug(f"Duplicate finding removed: {finding.title}")
        
        return unique_findings
    
    def calculate_cvss_score(self, finding: Finding) -> float:
        """
        CVSS score hesapla (basitleştirilmiş)
        
        CVSS v3.1 base score
        """
        
        # Risk level'a göre base score
        base_scores = {
            RiskLevel.CRITICAL: 9.5,
            RiskLevel.HIGH: 8.0,
            RiskLevel.MEDIUM: 6.0,
            RiskLevel.LOW: 3.5,
            RiskLevel.INFO: 0.0,
        }
        
        base = base_scores.get(finding.risk_level, 5.0)
        
        # Modifiers
        if "remote" in finding.description.lower():
            base += 0.3
        
        if "authentication" not in finding.description.lower():
            base += 0.2
        
        # Cap at 10.0
        return min(base, 10.0)
