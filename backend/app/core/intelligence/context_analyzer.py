"""
Context Analyzer - Understands exposure, auth barriers, and attack value.

Answers:
- Is this public or behind auth?
- What's the business value of this surface?
- How does context amplify risk?
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from enum import Enum

from app.utils.logger import logger


class ExposureLevel(str, Enum):
    """Asset exposure classification"""
    PUBLIC = "public"               # Internet-facing, no auth
    AUTH_REQUIRED = "auth_required" # Behind login
    ADMIN_SURFACE = "admin_surface" # Admin/privileged area
    INTERNAL = "internal"           # Internal network (future)


class BusinessValue(str, Enum):
    """Asset business criticality"""
    CRITICAL = "critical"  # Auth, payment, admin
    HIGH = "high"          # User data, sessions
    MEDIUM = "medium"      # Public content with forms
    LOW = "low"            # Static assets


class ContextAnalyzer:
    """
    Analyzes target context to inform risk decisions.
    
    This is NOT about finding vulnerabilities.
    This is about understanding WHERE you found them.
    """
    
    def __init__(self):
        self.logger = logger.bind(component="ContextAnalyzer")
        
        # Auth/admin indicators
        self.auth_indicators = [
            "login", "signin", "auth", "session", 
            "account", "profile", "dashboard",
            "oauth", "sso", "saml"
        ]
        
        self.admin_indicators = [
            "admin", "manage", "console", "cp",
            "backend", "cms", "panel", "portal"
        ]
        
        # High-value targets
        self.critical_paths = [
            "api", "graphql", "checkout", "payment",
            "cart", "order", "invoice", "billing"
        ]
    
    def analyze_finding_context(
        self,
        finding_url: str,
        evidence: Dict[str, Any],
        related_findings: List[Any] = None
    ) -> Dict[str, Any]:
        """
        Analyze context for a single finding.
        
        Returns:
            {
                "exposure": ExposureLevel,
                "business_value": BusinessValue,
                "auth_barrier_present": bool,
                "high_value_surface": bool,
                "context_notes": List[str]
            }
        """
        
        parsed = urlparse(finding_url)
        path = parsed.path.lower()
        
        context_notes = []
        
        # 1. Exposure analysis
        exposure = self._classify_exposure(path, evidence, context_notes)
        
        # 2. Business value
        business_value = self._assess_business_value(path, evidence, context_notes)
        
        # 3. Auth barrier
        auth_barrier = self._detect_auth_barrier(path, evidence, related_findings, context_notes)
        
        # 4. High-value surface flag
        high_value = (
            exposure == ExposureLevel.ADMIN_SURFACE or
            business_value in [BusinessValue.CRITICAL, BusinessValue.HIGH] or
            any(indicator in path for indicator in self.critical_paths)
        )
        
        return {
            "exposure": exposure,
            "business_value": business_value,
            "auth_barrier_present": auth_barrier,
            "high_value_surface": high_value,
            "context_notes": context_notes,
        }
    
    def _classify_exposure(
        self,
        path: str,
        evidence: Dict[str, Any],
        notes: List[str]
    ) -> ExposureLevel:
        """Determine if asset is public, auth-gated, or admin"""
        
        # Admin surface check
        if any(indicator in path for indicator in self.admin_indicators):
            notes.append("Admin surface detected")
            return ExposureLevel.ADMIN_SURFACE
        
        # Auth surface check
        if any(indicator in path for indicator in self.auth_indicators):
            notes.append("Auth surface detected")
            return ExposureLevel.AUTH_REQUIRED
        
        # Check evidence for auth signals
        if evidence:
            headers = str(evidence.get("headers", "")).lower()
            if "www-authenticate" in headers or "authorization" in headers:
                notes.append("Auth headers present")
                return ExposureLevel.AUTH_REQUIRED
            
            status = evidence.get("status_code", 0)
            if status in [401, 403]:
                notes.append("Auth required (401/403)")
                return ExposureLevel.AUTH_REQUIRED
        
        # Default: public
        return ExposureLevel.PUBLIC
    
    def _assess_business_value(
        self,
        path: str,
        evidence: Dict[str, Any],
        notes: List[str]
    ) -> BusinessValue:
        """Assess business criticality of the asset"""
        
        # Critical: auth, payment, admin
        critical_signals = self.admin_indicators + ["payment", "checkout", "api", "graphql"]
        if any(sig in path for sig in critical_signals):
            notes.append("Critical business function")
            return BusinessValue.CRITICAL
        
        # High: user data, sessions
        high_signals = ["user", "account", "profile", "session", "token"]
        if any(sig in path for sig in high_signals):
            notes.append("User data surface")
            return BusinessValue.HIGH
        
        # Medium: forms, search
        medium_signals = ["search", "contact", "form", "submit"]
        if any(sig in path for sig in medium_signals):
            return BusinessValue.MEDIUM
        
        # Low: static content
        return BusinessValue.LOW
    
    def _detect_auth_barrier(
        self,
        path: str,
        evidence: Dict[str, Any],
        related_findings: List[Any],
        notes: List[str]
    ) -> bool:
        """Detect if there's an authentication barrier"""
        
        # Direct evidence
        status = evidence.get("status_code", 0)
        if status in [401, 403]:
            notes.append("Auth barrier confirmed (HTTP 401/403)")
            return True
        
        # Related findings check (cross-reference)
        if related_findings:
            for f in related_findings:
                if hasattr(f, 'evidence'):
                    if f.evidence.get("status_code") in [401, 403]:
                        notes.append("Auth barrier detected in related finding")
                        return True
        
        return False
    
    def analyze_attack_surface(
        self,
        all_findings: List[Any]
    ) -> Dict[str, Any]:
        """
        Holistic attack surface analysis.
        
        Returns summary of:
        - Total public vs protected endpoints
        - Admin surface exposure
        - High-value targets identified
        """
        
        exposure_counts = {
            ExposureLevel.PUBLIC: 0,
            ExposureLevel.AUTH_REQUIRED: 0,
            ExposureLevel.ADMIN_SURFACE: 0,
        }
        
        high_value_count = 0
        admin_paths = []
        auth_paths = []
        
        for finding in all_findings:
            ctx = self.analyze_finding_context(
                finding.affected_url,
                finding.evidence or {},
                []
            )
            
            exposure = ctx["exposure"]
            exposure_counts[exposure] += 1
            
            if ctx["high_value_surface"]:
                high_value_count += 1
            
            if exposure == ExposureLevel.ADMIN_SURFACE:
                admin_paths.append(finding.affected_url)
            elif exposure == ExposureLevel.AUTH_REQUIRED:
                auth_paths.append(finding.affected_url)
        
        return {
            "exposure_distribution": {
                "public": exposure_counts[ExposureLevel.PUBLIC],
                "auth_required": exposure_counts[ExposureLevel.AUTH_REQUIRED],
                "admin_surface": exposure_counts[ExposureLevel.ADMIN_SURFACE],
            },
            "high_value_targets": high_value_count,
            "admin_paths_discovered": admin_paths[:5],  # Top 5
            "auth_paths_discovered": auth_paths[:5],
            "attack_surface_summary": self._generate_surface_summary(
                exposure_counts, high_value_count
            )
        }
    
    def _generate_surface_summary(
        self,
        exposure_counts: Dict[ExposureLevel, int],
        high_value_count: int
    ) -> str:
        """Generate human-readable attack surface summary"""
        
        admin = exposure_counts[ExposureLevel.ADMIN_SURFACE]
        auth = exposure_counts[ExposureLevel.AUTH_REQUIRED]
        public = exposure_counts[ExposureLevel.PUBLIC]
        
        if admin > 0:
            return f"Admin surface exposed ({admin} findings). High-risk scenario."
        elif high_value_count > 3:
            return f"{high_value_count} high-value targets identified. Prioritize review."
        elif auth > 5:
            return f"Significant auth surface ({auth} findings). Review auth mechanisms."
        elif public > 10:
            return f"Large public surface ({public} findings). Standard web app."
        else:
            return "Limited attack surface. Low-risk target."


__all__ = ["ContextAnalyzer", "ExposureLevel", "BusinessValue"]
