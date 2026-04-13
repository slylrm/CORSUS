"""
Severity Engine - Context-Aware Risk Scoring

Replaces static severity with explainable, context-driven decisions.

Formula:
final_severity = base_severity × context_multiplier × chain_multiplier

Context matters:
- Missing header on public landing page ≠ missing header on admin login
- Old TLS on CDN ≠ old TLS on payment endpoint
"""

from typing import Dict, Any, List, Optional
from enum import Enum

from app.tools.base import RiskLevel
from app.core.intelligence.context_analyzer import (
    ExposureLevel, BusinessValue
)
from app.utils.logger import logger


class SeverityReason(str, Enum):
    """Why severity was adjusted"""
    HIGH_VALUE_TARGET = "high_value_target"
    ADMIN_SURFACE = "admin_surface"
    AUTH_BYPASS_POTENTIAL = "auth_bypass_potential"
    CHAIN_AMPLIFICATION = "chain_amplification"
    PUBLIC_LOW_IMPACT = "public_low_impact"
    NO_AUTH_BARRIER = "no_auth_barrier"
    REPRODUCIBLE = "reproducible"
    LIMITED_EXPOSURE = "limited_exposure"


class SeverityEngine:
    """
    Context-aware severity calculator.
    
    Base severity comes from tool/vuln type.
    Context multiplier adjusts for exposure/auth/value.
    Chain multiplier boosts correlated risks.
    """
    
    def __init__(self):
        self.logger = logger.bind(component="SeverityEngine")
        
        # Base severity weights
        self.severity_weights = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 1,
        }
    
    def calculate_severity(
        self,
        base_severity: RiskLevel,
        context: Dict[str, Any],
        is_correlated: bool = False,
        correlated_count: int = 1,
        evidence_quality: float = 0.5,
        exploitability: float = 0.5
    ) -> Dict[str, Any]:
        """
        Calculate context-aware severity.
        
        Args:
            base_severity: Tool/vuln-provided severity
            context: From ContextAnalyzer
            is_correlated: Part of attack chain?
            correlated_count: How many findings in chain
            evidence_quality: Quality of evidence (0-1)
            exploitability: Ease of exploitation (0-1)
        
        Returns:
            {
                "final_severity": RiskLevel,
                "base_severity": RiskLevel,
                "context_multiplier": float,
                "chain_multiplier": float,
                "severity_reasons": List[str],
                "explanation": str
            }
        """
        
        base_weight = self.severity_weights[base_severity]
        multipliers = []
        reasons = []
        
        # 1. Context multiplier
        context_mult = self._calculate_context_multiplier(
            context, reasons
        )
        multipliers.append(("context", context_mult))
        
        # 2. Chain multiplier
        chain_mult = 1.0
        if is_correlated and correlated_count > 1:
            chain_mult = 1.0 + (0.2 * min(correlated_count - 1, 3))  # Max +60%
            reasons.append(SeverityReason.CHAIN_AMPLIFICATION)
            multipliers.append(("chain", chain_mult))
        
        # 3. Evidence quality factor
        if evidence_quality < 0.6:
            # Low evidence = reduce severity
            context_mult *= 0.85
            reasons.append(SeverityReason.LIMITED_EXPOSURE)
        elif evidence_quality > 0.85:
            # High evidence = slight boost
            context_mult *= 1.1
            reasons.append(SeverityReason.REPRODUCIBLE)
        
        # Calculate final weight
        final_weight = base_weight * context_mult * chain_mult
        
        # Map back to severity level
        final_severity = self._weight_to_severity(final_weight)
        
        # Generate explanation
        explanation = self._generate_explanation(
            base_severity,
            final_severity,
            context,
            is_correlated,
            reasons
        )
        
        self.logger.info(
            f"Severity calc: {base_severity.value} → {final_severity.value}",
            extra={
                "context_mult": f"{context_mult:.2f}",
                "chain_mult": f"{chain_mult:.2f}",
                "reasons": [r.value for r in reasons]
            }
        )
        
        return {
            "final_severity": final_severity,
            "base_severity": base_severity,
            "context_multiplier": context_mult,
            "chain_multiplier": chain_mult,
            "severity_reasons": [r.value for r in reasons],
            "explanation": explanation,
        }
    
    def _calculate_context_multiplier(
        self,
        context: Dict[str, Any],
        reasons: List[SeverityReason]
    ) -> float:
        """
        Calculate multiplier based on context.
        
        High value target = amplify
        Public low-impact = reduce
        Admin surface = amplify
        """
        
        multiplier = 1.0
        
        exposure = context.get("exposure")
        business_value = context.get("business_value")
        auth_barrier = context.get("auth_barrier_present", False)
        high_value = context.get("high_value_surface", False)
        
        # Admin surface: +40%
        if exposure == ExposureLevel.ADMIN_SURFACE:
            multiplier *= 1.4
            reasons.append(SeverityReason.ADMIN_SURFACE)
        
        # High-value target: +30%
        elif high_value or business_value == BusinessValue.CRITICAL:
            multiplier *= 1.3
            reasons.append(SeverityReason.HIGH_VALUE_TARGET)
        
        # Auth required but issue exists: +20%
        elif exposure == ExposureLevel.AUTH_REQUIRED and not auth_barrier:
            multiplier *= 1.2
            reasons.append(SeverityReason.AUTH_BYPASS_POTENTIAL)
        
        # Public + low business value: -30%
        elif exposure == ExposureLevel.PUBLIC and business_value == BusinessValue.LOW:
            multiplier *= 0.7
            reasons.append(SeverityReason.PUBLIC_LOW_IMPACT)
        
        # No auth on sensitive surface: amplify
        elif not auth_barrier and business_value in [BusinessValue.HIGH, BusinessValue.CRITICAL]:
            multiplier *= 1.25
            reasons.append(SeverityReason.NO_AUTH_BARRIER)
        
        return multiplier
    
    def _weight_to_severity(self, weight: float) -> RiskLevel:
        """Map numeric weight back to severity level"""
        
        if weight >= 5.0:
            return RiskLevel.CRITICAL
        elif weight >= 3.5:
            return RiskLevel.HIGH
        elif weight >= 2.0:
            return RiskLevel.MEDIUM
        elif weight >= 1.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _generate_explanation(
        self,
        base: RiskLevel,
        final: RiskLevel,
        context: Dict[str, Any],
        is_correlated: bool,
        reasons: List[SeverityReason]
    ) -> str:
        """Generate human-readable severity explanation"""
        
        if base == final:
            return f"Severity {final.value}: standard risk level maintained."
        
        exposure = context.get("exposure", "unknown")
        business_value = context.get("business_value", "unknown")
        
        parts = [f"Severity adjusted from {base.value} to {final.value}"]
        
        if SeverityReason.ADMIN_SURFACE in reasons:
            parts.append("admin surface detected")
        
        if SeverityReason.HIGH_VALUE_TARGET in reasons:
            parts.append(f"high-value target ({business_value})")
        
        if SeverityReason.CHAIN_AMPLIFICATION in reasons:
            parts.append("part of attack chain")
        
        if SeverityReason.PUBLIC_LOW_IMPACT in reasons:
            parts.append("public surface with low business impact")
        
        if SeverityReason.NO_AUTH_BARRIER in reasons:
            parts.append("no authentication barrier on sensitive surface")
        
        return " - ".join(parts) + "."
    
    def recalculate_correlated_risk_severity(
        self,
        correlated_risk: Dict[str, Any],
        findings: List[Any]
    ) -> RiskLevel:
        """
        Calculate severity for a correlated risk bundle.
        
        Takes into account:
        - Highest individual severity
        - Number of findings
        - Context of affected endpoints
        """
        
        if not findings:
            return RiskLevel.MEDIUM
        
        # Get highest base severity
        max_severity = max(
            [f.risk_level for f in findings],
            key=lambda s: self.severity_weights[s]
        )
        
        # Analyze context of first finding (representative)
        first_finding = findings[0]
        context = correlated_risk.get("context", {})
        
        # Apply context-aware calculation
        result = self.calculate_severity(
            base_severity=max_severity,
            context=context,
            is_correlated=True,
            correlated_count=len(findings),
            evidence_quality=correlated_risk.get("confidence_score", 0.7),
            exploitability=correlated_risk.get("exploitability_score", 0.5)
        )
        
        return result["final_severity"]


__all__ = ["SeverityEngine", "SeverityReason"]
