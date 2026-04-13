"""
Cross-Validation Service
Farklı tool'lardan gelen finding'leri karşılaştırır ve doğrular
"""

from typing import List, Dict, Tuple
import difflib
from app.core.scanner import Finding, RiskLevel, VerificationStatus
from app.utils.logger import logger


class CrossValidator:
    """Farklı tool sonuçlarını karşılaştırır ve normalize eder"""
    
    def __init__(self):
        self.logger = logger.bind(component="CrossValidator")
    
    def cross_validate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Aynı vulnerability'leri birleştir ve confidence'i ayarla
        
        - Aynı endpoint + parametre + payload = aynı bulgu
        - 2+ tool'dan gelirse CRITICAL/HIGH olabilir
        - Tek tool'dan gelirse HIGH->MEDIUM, CRITICAL->HIGH indirgenir
        """
        
        if not findings:
            return []
        
        # Finding'leri normalize et
        normalized = self._normalize_findings(findings.copy())
        
        # Benzer finding'leri grupla
        groups = self._group_similar_findings(normalized)
        
        # Her grup için validation yapılsın
        validated = []
        for group in groups:
            merged = self._merge_findings(group)
            validated.append(merged)
        
        self.logger.info(f"Cross-validation: {len(findings)} findings grouped into {len(validated)}")
        
        return validated
    
    def _normalize_findings(self, findings: List[Finding]) -> List[Finding]:
        """Finding'leri normalize et (endpoint, parameter vb.)"""
        
        for finding in findings:
            try:
                # URL'den query parametresini ayır
                if "?" in finding.affected_url:
                    finding.affected_url = finding.affected_url.split("?")[0]
                
                # Risk level'i lowercase'e çevir (consistency)
                finding.risk_level = RiskLevel(finding.risk_level.value)
            except Exception as e:
                self.logger.warning(f"Normalization error for finding: {e}")
        
        return findings
    
    def _group_similar_findings(self, findings: List[Finding]) -> List[List[Finding]]:
        """Benzer finding'leri grupla (endpoint, parameter, payload match)"""
        
        groups = []
        used = set()
        
        for i, f1 in enumerate(findings):
            if i in used:
                continue
            
            group = [f1]
            used.add(i)
            
            for j, f2 in enumerate(findings[i+1:], start=i+1):
                if j in used:
                    continue
                
                # Similarity check
                similarity = self._calculate_similarity(f1, f2)
                
                if similarity > 0.75:  # 75% benzer
                    group.append(f2)
                    used.add(j)
                    self.logger.debug(f"Grouped findings: {f1.title} + {f2.title} ({similarity:.2%})")
            
            groups.append(group)
        
        return groups
    
    def _calculate_similarity(self, f1: Finding, f2: Finding) -> float:
        """İki finding arasındaki benzerliği hesapla (0.0 - 1.0)"""
        
        similarity = 0.0
        
        # Affected URL benzerliği (40% weight)
        if f1.affected_url == f2.affected_url:
            similarity += 0.4
        else:
            url_ratio = difflib.SequenceMatcher(
                None, 
                f1.affected_url.lower(), 
                f2.affected_url.lower()
            ).ratio()
            similarity += url_ratio * 0.4
        
        # Title benzerliği (30% weight)
        title_ratio = difflib.SequenceMatcher(
            None,
            f1.title.lower(),
            f2.title.lower()
        ).ratio()
        similarity += title_ratio * 0.3
        
        # CWE match (20% weight)
        if f1.cwe_id and f2.cwe_id:
            if f1.cwe_id == f2.cwe_id:
                similarity += 0.2
        else:
            # CWE match kısmen
            cwe_ratio = 0.1 if (f1.cwe_id or f2.cwe_id) else 0.0
            similarity += cwe_ratio
        
        # Risk level match (10% weight)
        if f1.risk_level == f2.risk_level:
            similarity += 0.1
        
        return min(similarity, 1.0)
    
    def _merge_findings(self, group: List[Finding]) -> Finding:
        """
        Aynı bulguları merge et
        - Confidence arttır (multi-tool bonus)
        - Severity kurallarını uygula (tek tool kuralı)
        """
        
        if len(group) == 1:
            finding = group[0]
            # Tek tool'dan gelen finding'ler için şiddeti kontrol et
            finding = self._enforce_single_tool_rules(finding)
            return finding
        
        # En yüksek confidence'e sahip olanı base olarak kullan
        main = max(group, key=lambda f: f.confidence_score)
        
        # Sources listesini birleştir
        all_sources = set()
        for f in group:
            all_sources.update(f.sources or [])
        
        main.sources = list(all_sources)
        
        # ✅ CROSS-VALIDATION BONUS: 2+ tool'dan gelmişse confidence artır
        base_confidence = main.confidence_score
        source_count = len(main.sources)
        
        if source_count >= 2:
            # Multi-source bonus
            validation_bonus = 0.15 * min(source_count - 1, 2)  # Max 30% bonus
            main.confidence_score = min(base_confidence + validation_bonus, 1.0)
            main.verification_status = VerificationStatus.VERIFIED
            self.logger.info(f"Multi-tool verification: {main.title} (+{validation_bonus:.0%} confidence)")
        else:
            # Tek tool - severity kurallarını uygula
            main = self._enforce_single_tool_rules(main)
        
        # Evidence'leri merge et
        if isinstance(main.evidence, dict):
            for f in group[1:]:
                if isinstance(f.evidence, dict) and f.sources:
                    tool_name = f.sources[0] if f.sources else "unknown"
                    main.evidence[f"evidence_from_{tool_name}"] = f.evidence
        
        self.logger.info(f"Merged {len(group)} findings: {main.title} (sources: {','.join(main.sources)})")
        
        return main
    
    def _enforce_single_tool_rules(self, finding: Finding) -> Finding:
        """
        Tek tool'dan gelen finding'leri CRITICAL olamaz kuralı
        """
        
        tool_count = len(finding.sources or [1])
        
        if tool_count == 1:
            # Tek tool kuralı
            if finding.risk_level == RiskLevel.CRITICAL:
                finding.risk_level = RiskLevel.HIGH
                finding.low_confidence_reason = "Single tool detection - requires manual verification"
                self.logger.warning(f"Downgraded to HIGH: {finding.title} (single tool)")
            
            # Confidence sınırı: 0.85 üstüne çıkmaması gerekir
            if finding.confidence_score > 0.85:
                finding.confidence_score = 0.85
                finding.verification_status = VerificationStatus.NEEDS_MANUAL
                finding.is_low_confidence = True
            
            # Manual verification gerekli
            if finding.verification_status == VerificationStatus.UNVERIFIED:
                finding.verification_status = VerificationStatus.NEEDS_MANUAL
        
        return finding
    
    def validate_by_payload_matching(self, findings: List[Finding]) -> List[Finding]:
        """
        Payload'ları karşılaştırarak validation yap
        
        Aynı endpoint + parametre + payload = confirmed
        """
        
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                if not self._payloads_match(f1, f2):
                    continue
                
                # Payload match bulundu
                f1.verification_status = VerificationStatus.VERIFIED
                f2.verification_status = VerificationStatus.VERIFIED
                f1.confidence_score = min(f1.confidence_score + 0.15, 1.0)
                f2.confidence_score = min(f2.confidence_score + 0.15, 1.0)
                
                self.logger.info(f"Payload match validated: {f1.title}")
        
        return findings
    
    def _payloads_match(self, f1: Finding, f2: Finding) -> bool:
        """İki finding'in payload'u eşleşiyor mu?"""
        
        try:
            p1 = f1.evidence.get("payload", "")
            p2 = f2.evidence.get("payload", "")
            
            e1 = f1.evidence.get("endpoint", "") or f1.affected_url
            e2 = f2.evidence.get("endpoint", "") or f2.affected_url
            
            param1 = f1.evidence.get("parameter", "")
            param2 = f2.evidence.get("parameter", "")
            
            return (
                p1 and p2 and p1 == p2 and
                e1 == e2 and
                param1 and param2 and param1 == param2
            )
        except:
            return False
