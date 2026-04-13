"""
Adaptive Depth Controller - Smart, Not Loud

Adjusts scan depth based on discovered surface value.

Rules:
1. Default: shallow scan (depth=2)
2. Auth surface detected → increase auth-path depth to 3
3. Admin panel found → limited enumeration (depth=3, specific paths only)
4. Nothing valuable → early stop
5. NEVER increase global depth blindly
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from app.utils.logger import logger


class ScanDepthDecision:
    """Encapsulates a depth adjustment decision"""
    
    def __init__(
        self,
        should_adjust: bool,
        new_depth: int,
        scope_filter: Optional[str] = None,
        reason: str = ""
    ):
        self.should_adjust = should_adjust
        self.new_depth = new_depth
        self.scope_filter = scope_filter  # Path prefix to limit depth increase
        self.reason = reason


class AdaptiveDepthController:
    """
    Controls scan depth based on discovered attack surface value.
    
    This is NOT a blind depth increase.
    This is targeted depth adjustment for high-value surfaces.
    """
    
    def __init__(self, default_depth: int = 2):
        self.logger = logger.bind(component="AdaptiveDepthController")
        self.default_depth = default_depth
        self.max_safe_depth = 4  # Hard limit
        
        # Depth triggers
        self.auth_indicators = ["login", "signin", "auth", "account", "session"]
        self.admin_indicators = ["admin", "manage", "console", "dashboard", "cp"]
        self.high_value_indicators = ["api", "graphql", "checkout", "payment"]
    
    def decide_depth_adjustment(
        self,
        discovered_urls: List[str],
        current_depth: int,
        findings_so_far: int
    ) -> ScanDepthDecision:
        """
        Decide if scan depth should be adjusted.
        
        Args:
            discovered_urls: URLs discovered so far
            current_depth: Current crawl depth
            findings_so_far: Number of findings
        
        Returns:
            ScanDepthDecision with adjustment details
        """
        
        # Already at max? No adjustment
        if current_depth >= self.max_safe_depth:
            return ScanDepthDecision(
                should_adjust=False,
                new_depth=current_depth,
                reason="Already at maximum safe depth"
            )
        
        # Analyze discovered surface
        has_auth_surface = self._detect_auth_surface(discovered_urls)
        has_admin_surface = self._detect_admin_surface(discovered_urls)
        has_high_value = self._detect_high_value(discovered_urls)
        
        # Admin surface: increase depth for admin paths only
        if has_admin_surface:
            admin_prefix = self._extract_admin_prefix(discovered_urls)
            return ScanDepthDecision(
                should_adjust=True,
                new_depth=min(current_depth + 1, 3),
                scope_filter=admin_prefix,
                reason=f"Admin surface detected at {admin_prefix}; increasing depth for admin paths"
            )
        
        # Auth surface: increase depth for auth paths only
        if has_auth_surface:
            auth_prefix = self._extract_auth_prefix(discovered_urls)
            return ScanDepthDecision(
                should_adjust=True,
                new_depth=min(current_depth + 1, 3),
                scope_filter=auth_prefix,
                reason=f"Auth surface detected at {auth_prefix}; increasing depth for auth paths"
            )
        
        # High-value API: controlled increase
        if has_high_value:
            return ScanDepthDecision(
                should_adjust=True,
                new_depth=min(current_depth + 1, 3),
                scope_filter=None,  # Global but limited
                reason="High-value API surface detected; controlled depth increase"
            )
        
        # Nothing valuable and few findings? Consider early stop
        if findings_so_far < 3 and current_depth >= 2:
            return ScanDepthDecision(
                should_adjust=True,
                new_depth=current_depth,  # No change, but signal to consider stopping
                reason="Limited findings; consider early completion"
            )
        
        # Default: no adjustment
        return ScanDepthDecision(
            should_adjust=False,
            new_depth=current_depth,
            reason="Standard depth maintained"
        )
    
    def _detect_auth_surface(self, urls: List[str]) -> bool:
        """Detect if authentication surface is present"""
        return any(
            any(indicator in url.lower() for indicator in self.auth_indicators)
            for url in urls
        )
    
    def _detect_admin_surface(self, urls: List[str]) -> bool:
        """Detect if admin surface is present"""
        return any(
            any(indicator in url.lower() for indicator in self.admin_indicators)
            for url in urls
        )
    
    def _detect_high_value(self, urls: List[str]) -> bool:
        """Detect high-value endpoints"""
        return any(
            any(indicator in url.lower() for indicator in self.high_value_indicators)
            for url in urls
        )
    
    def _extract_admin_prefix(self, urls: List[str]) -> str:
        """Extract common admin path prefix"""
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            for indicator in self.admin_indicators:
                if indicator in path:
                    # Extract prefix up to indicator
                    idx = path.find(indicator)
                    return path[:idx + len(indicator)]
        return "/admin"
    
    def _extract_auth_prefix(self, urls: List[str]) -> str:
        """Extract common auth path prefix"""
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            for indicator in self.auth_indicators:
                if indicator in path:
                    idx = path.find(indicator)
                    return path[:idx + len(indicator)]
        return "/login"
    
    def should_continue_scan(
        self,
        elapsed_minutes: float,
        findings_count: int,
        tools_completed: int,
        total_tools: int
    ) -> Dict[str, Any]:
        """
        Decide if scan should continue or early-stop.
        
        Early stop criteria:
        - No findings after 50% of tools
        - Very few findings and significant time elapsed
        - All critical checks done
        
        Returns:
            {
                "should_continue": bool,
                "reason": str,
                "recommendation": str
            }
        """
        
        progress = tools_completed / total_tools if total_tools > 0 else 0
        
        # No findings after 50% progress? Consider stopping
        if progress > 0.5 and findings_count == 0:
            return {
                "should_continue": False,
                "reason": "No findings after 50% of tools completed",
                "recommendation": "Target appears secure or well-hardened; consider stopping"
            }
        
        # Very few findings and long time? Consider stopping
        if elapsed_minutes > 10 and findings_count < 2:
            return {
                "should_continue": False,
                "reason": f"Only {findings_count} findings after {elapsed_minutes:.1f} minutes",
                "recommendation": "Low-risk target; remaining tools unlikely to yield significant findings"
            }
        
        # Continue by default
        return {
            "should_continue": True,
            "reason": f"Scan progressing: {findings_count} findings, {progress:.0%} complete",
            "recommendation": "Continue with remaining tools"
        }


__all__ = ["AdaptiveDepthController", "ScanDepthDecision"]
