"""
Scan Thinking Engine

Observes scan-level signals (across findings) and makes run-time decisions.

Decisions (per scan):
- STOP_SCAN: halt remaining tools, no further value
- REDUCE_DEPTH: limit noisy probing (future hooks can use this flag)
- ESCALATE: raise priority because a pattern is forming
- CONTINUE: keep scanning as normal

Rules (lightweight, non-invasive):
- Hygiene cluster: many LOW/INFO on same surface -> REDUCE_DEPTH
- Admin STOP observed -> prevent deeper admin probing
- No exploitable chain after threshold -> STOP_SCAN (avoid noise)
- Emerging narrative (chains/high on admin/auth) -> ESCALATE

No exploitation/state change is performed; this is advisory control.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, TYPE_CHECKING, Any

from app.tools.base import RiskLevel

if TYPE_CHECKING:
    from app.core.scanner import Finding, Scan


class ScanDecisionType(str, Enum):
    STOP_SCAN = "STOP_SCAN"
    REDUCE_DEPTH = "REDUCE_DEPTH"
    ESCALATE = "ESCALATE"
    CONTINUE = "CONTINUE"


@dataclass
class ScanDecision:
    decision: ScanDecisionType
    reason: str
    surface: Optional[str] = None


class ScanThinkingEngine:
    """Maintains scan-level state and issues decisions."""

    def __init__(self, hygiene_threshold: int = 5, chain_gap: int = 12):
        self.hygiene_threshold = hygiene_threshold
        self.chain_gap = chain_gap

    def observe(self, scan: Any, finding: Any) -> ScanDecision:
        """Update scan state with a finding and emit a decision."""

        # Track counts
        surface = getattr(finding, "surface", None) or "unknown"
        scan.surface_counts[surface] = scan.surface_counts.get(surface, 0) + 1
        lvl = finding.risk_level.value if hasattr(finding, "risk_level") else "info"
        scan.severity_counts[lvl] = scan.severity_counts.get(lvl, 0) + 1

        if finding.stop_reason:
            scan.stop_events.append({"surface": surface, "reason": finding.stop_reason})

        # Hygiene clustering rule (many low/info on same surface)
        if lvl in [RiskLevel.INFO.value, RiskLevel.LOW.value]:
            key = (surface, "hygiene")
            scan.hygiene_counts[key] = scan.hygiene_counts.get(key, 0) + 1
            if scan.hygiene_counts[key] >= self.hygiene_threshold:
                return ScanDecision(
                    decision=ScanDecisionType.REDUCE_DEPTH,
                    reason=f"Hygiene cluster detected on surface {surface} (>= {self.hygiene_threshold} low/info findings)",
                    surface=surface,
                )

        # Admin STOP rule
        if finding.stop_reason and "admin" in finding.stop_reason.lower():
            return ScanDecision(
                decision=ScanDecisionType.STOP_SCAN,
                reason="Admin surface STOP triggered; halting to avoid deeper admin probing",
                surface=surface,
            )

        # No attack chain after N findings => low value
        scan.total_processed += 1
        if scan.total_processed >= self.chain_gap:
            chains = scan.chains_observed + (1 if finding.attack_chain else 0)
            if chains == 0:
                return ScanDecision(
                    decision=ScanDecisionType.STOP_SCAN,
                    reason=f"No exploitable chain after {scan.total_processed} findings; stopping early to avoid noise",
                )

        # Attack narrative forming
        if finding.attack_chain or lvl in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
            scan.chains_observed += 1 if finding.attack_chain else 0
            if surface in ["admin", "auth"] or scan.chains_observed >= 2:
                return ScanDecision(
                    decision=ScanDecisionType.ESCALATE,
                    reason="Attack narrative forming (chain/high severity on privileged surface)",
                    surface=surface,
                )

        return ScanDecision(decision=ScanDecisionType.CONTINUE, reason="Continue scanning")


__all__ = ["ScanThinkingEngine", "ScanDecision", "ScanDecisionType"]
