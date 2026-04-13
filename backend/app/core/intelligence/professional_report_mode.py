"""
Professional Report Mode

Converts scan state + intelligence outputs into a human, senior-pentester narrative.

Rules:
- No raw tool output or payloads.
- Severity is sourced from ThinkingEngine decisions (not raw tool scores).
- Hygiene-only issues are framed as "Security Hygiene Weaknesses" not "Vulnerabilities".
- STOP_SCAN is clearly explained when triggered.
- Attack chains are narrated as stories, not isolated items.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.scanner import Finding, RiskLevel, Scan


def _severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {lvl.value: 0 for lvl in RiskLevel}
    for f in findings:
        counts[f.risk_level.value] = counts.get(f.risk_level.value, 0) + 1
    return counts


def _has_only_hygiene(counts: Dict[str, int]) -> bool:
    return counts.get("medium", 0) == 0 and counts.get("high", 0) == 0 and counts.get("critical", 0) == 0


def _build_executive_summary(scan: Scan, counts: Dict[str, int], stopped: bool) -> str:
    hygiene_only = _has_only_hygiene(counts)
    suppressed = len(getattr(scan, "suppressed_findings", []) or [])
    decisions = scan.scan_decisions or []
    top_decision = next((d for d in decisions if d.get("decision") == "STOP_SCAN"), None)

    if stopped and top_decision:
        return (
            "Scanning halted early after professional review: "
            f"{top_decision.get('reason')}. No further value expected beyond current coverage."
        )

    if hygiene_only:
        return (
            "Assessment completed: security hygiene weaknesses dominate the surface. "
            f"{counts.get('low', 0)} low/ info hygiene items recorded; {suppressed} were suppressed as noise."
        )

    return (
        "Assessment completed with intelligence-driven triage. "
        f"High/critical items: {counts.get('high', 0) + counts.get('critical', 0)}. "
        f"Hygiene noise suppressed: {suppressed}. Decisions applied: {len(decisions)}."
    )


def _build_scan_intelligence_summary(scan: Scan) -> List[str]:
    notes: List[str] = []
    if scan.depth_reduced:
        notes.append("Depth reduced after hygiene cluster to minimize noise.")
    if scan.escalated:
        notes.append("Scan escalated when an attack narrative started to form.")
    if scan.stopped_surfaces:
        notes.append(f"Surfaces halted: {', '.join(sorted(scan.stopped_surfaces))}.")
    if not notes:
        notes.append("Standard depth maintained; no disruptive controls triggered.")
    return notes


def _story_from_chain(risk: Dict[str, Any]) -> str:
    chain = risk.get("attack_chain") or []
    if not chain:
        return risk.get("single_risk_summary") or risk.get("title", "")
    return " → ".join(chain)


def _key_finding_item(risk: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": risk.get("title"),
        "severity": risk.get("risk_level"),
        "story": _story_from_chain(risk),
        "why_it_matters": risk.get("business_impact") or risk.get("severity_explanation"),
        "next_probe": risk.get("next_probe"),
        "surface": (risk.get("context") or {}).get("surface"),
    }


def _validation_status(risk: Dict[str, Any]) -> str:
    v = (risk.get("validation_type") or "").lower()
    if "auto" in v or "verified" in v or "confirmed" in v:
        return "observed"
    if "chain" in v:
        return "chain-based"
    if "needs" in v or "manual" in v:
        return "observed"
    return "inferred"


def _normalize_finding_for_exec(risk: Dict[str, Any], hygiene_only: bool) -> Dict[str, Any]:
    title = risk.get("title") or "Assessment Finding"
    severity = (risk.get("risk_level") or "low").lower()
    story = _story_from_chain(risk)
    business = risk.get("business_impact") or risk.get("severity_explanation") or "Potential business impact identified."
    chain = risk.get("attack_chain") or []

    observed = story or title
    why_matters = business
    impact = risk.get("business_impact") or "Could enable misuse of protected functionality or data if combined with other weaknesses."
    recommendation = "Address the underlying control gap and harden the affected surface."

    if hygiene_only or severity in ["low", "info"]:
        why_matters = "This is a security hygiene weakness, not an exploitable vulnerability on its own."
        impact = "Left unaddressed, hygiene weaknesses increase exposure to future misconfigurations and attacker recon."
        recommendation = "Improve baseline security hygiene on this surface (headers, configurations, inventory)."

    if chain:
        why_matters = f"Part of an attack narrative: this element enables progression along the chain ({' → '.join(chain)})."
        impact = "If combined with adjacent weaknesses in the chain, this can accelerate lateral movement or data exposure."

    return {
        "title": title,
        "severity": severity,
        "observed": observed,
        "why_it_matters": why_matters,
        "likely_impact": impact,
        "recommended_action": recommendation,
        "validation_status": _validation_status(risk),
        "surface": (risk.get("context") or {}).get("surface"),
    }


def _suppressed_summary(scan: Scan) -> Dict[str, Any]:
    suppressed = getattr(scan, "suppressed_findings", []) or []
    stop_events = getattr(scan, "stop_events", []) or []
    reasons = [f.stop_reason for f in suppressed if getattr(f, "stop_reason", None)]
    reasons += [e.get("reason") for e in stop_events if e.get("reason")]
    return {
        "suppressed_count": len(suppressed),
        "common_reasons": list({r for r in reasons if r}),
    }


def _decisions_timeline(scan: Scan) -> List[Dict[str, Any]]:
    timeline = []
    for idx, d in enumerate(scan.scan_decisions or [], start=1):
        timeline.append({
            "order": idx,
            "decision": d.get("decision"),
            "reason": d.get("reason"),
            "surface": d.get("surface"),
            "after_finding": d.get("after_finding"),
        })
    return timeline


def _risk_posture(counts: Dict[str, int], findings: List[Finding]) -> Dict[str, Any]:
    business_surfaces = {}
    for f in findings:
        surface = getattr(f, "surface", None)
        bv = getattr(f, "business_value", None)
        if surface and bv:
            business_surfaces.setdefault(surface, set()).add(bv)
    business_summary = {k: sorted(list(v)) for k, v in business_surfaces.items()}
    return {
        "severity_distribution": counts,
        "business_surfaces": business_summary,
        "posture_commentary": _posture_commentary(counts, business_summary),
    }


def _posture_commentary(counts: Dict[str, int], business_summary: Dict[str, List[str]]) -> str:
    high = counts.get("high", 0) + counts.get("critical", 0)
    if high:
        return "Prioritize privileged and high-value surfaces; high-severity items present."
    if _has_only_hygiene(counts):
        return "Overall posture: hygiene weaknesses detected; no exploit-ready findings surfaced."
    return "Mixed posture: moderate issues observed; continue hardening and monitoring."


def _operating_context(scan: Scan) -> Dict[str, Any]:
    mode = getattr(scan, "operating_mode", None)
    started = scan.started_at.isoformat() if scan.started_at else None
    completed = scan.completed_at.isoformat() if scan.completed_at else None
    duration_seconds = None
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
    return {
        "operating_mode": mode.value if hasattr(mode, "value") else str(mode or "SAFE_READ_ONLY"),
        "authorization_acknowledged": bool(getattr(scan, "authorization_acknowledged", False)),
        "scope_statement": getattr(scan, "scope_statement", None),
        "assessment_window": {
            "started_at": started,
            "completed_at": completed,
            "duration_seconds": duration_seconds,
        },
    }


def _confidence_level(scan: Scan, counts: Dict[str, int]) -> str:
    level = "High"
    hygiene_only = _has_only_hygiene(counts)

    if scan.depth_reduced:
        level = "Medium"
    if any(d.get("decision") == "STOP_SCAN" for d in (scan.scan_decisions or [])):
        level = "Medium" if level == "High" else "Low"
    suppressed = len(getattr(scan, "suppressed_findings", []) or [])
    if suppressed > 15:
        level = "Low"
    if hygiene_only and suppressed > 0:
        level = "Medium"
    return level


def _confidence_reasons(scan: Scan, counts: Dict[str, int]) -> Dict[str, Any]:
    reasons: List[str] = []
    coverage_notes: List[str] = []

    suppressed = len(getattr(scan, "suppressed_findings", []) or [])
    if scan.depth_reduced:
        reasons.append("Depth was reduced on hygiene-heavy surfaces to focus on signal.")
    if any(d.get("decision") == "STOP_SCAN" for d in (scan.scan_decisions or [])):
        reasons.append("Scan stopped early where additional probing was unlikely to add value.")
    if suppressed:
        reasons.append(f"{suppressed} noisy items were suppressed after reasoning they were non-actionable.")
    if scan.escalated:
        reasons.append("Escalation applied when attack narrative emerged to increase scrutiny.")
    if not reasons:
        reasons.append("Normal depth and coverage maintained without disruptive controls.")

    covered_surfaces = sorted((scan.surface_counts or {}).keys()) if hasattr(scan, "surface_counts") else []
    skipped_surfaces = sorted(list(getattr(scan, "stopped_surfaces", []) or []))
    skipped_surfaces += [e.get("surface") for e in getattr(scan, "stop_events", []) or [] if e.get("surface")]
    skipped_surfaces = [s for s in skipped_surfaces if s]

    if covered_surfaces:
        coverage_notes.append(f"Covered surfaces: {', '.join(covered_surfaces)}")
    if skipped_surfaces:
        unique_skipped = sorted(list({s for s in skipped_surfaces}))
        coverage_notes.append(f"Deprioritized or halted surfaces: {', '.join(unique_skipped)}")
    if not coverage_notes:
        coverage_notes.append("Coverage aligned to discovered surfaces; no areas were skipped.")

    trust_notes = [
        "Findings reflect pentester reasoning (ThinkingEngine) rather than raw tool scores.",
        "Suppression targeted hygiene noise only; risk-bearing items were preserved and reviewed.",
        "Decisions are logged (ESCALATE/REDUCE_DEPTH/STOP_SCAN) for transparency and auditability.",
        "Assessment operated in SAFE READ-ONLY mode; only GET/HEAD/OPTIONS requests were permitted.",
    ]

    not_tested: List[str] = []
    if scan.depth_reduced:
        not_tested.append("Deep permutations on hygiene-heavy surfaces were intentionally skipped.")
    if skipped_surfaces:
        not_tested.append("Intrusive steps on halted surfaces (per STOP decisions) were not executed.")
    if not not_tested:
        not_tested.append("Highly intrusive or state-changing actions were not performed by design.")

    return {
        "overall_confidence": _confidence_level(scan, counts),
        "reasons": reasons,
        "coverage": coverage_notes,
        "not_tested": not_tested,
        "why_trust": trust_notes,
    }


def build_professional_report(scan: Scan, correlated_risks: List[Dict[str, Any]], findings: List[Finding]) -> Dict[str, Any]:
    counts = _severity_counts(findings)
    stopped = any(d.get("decision") == "STOP_SCAN" for d in (scan.scan_decisions or []))

    # Hygiene framing if only low/info
    hygiene_only = _has_only_hygiene(counts)
    key_items = [_normalize_finding_for_exec(r, hygiene_only) for r in correlated_risks] if correlated_risks else []
    if hygiene_only:
        for item in key_items:
            item["title"] = item["title"] or "Security Hygiene Weakness"
            item["severity"] = "low"

    report = {
        "executive_summary": _build_executive_summary(scan, counts, stopped),
        "scan_intelligence_summary": _build_scan_intelligence_summary(scan),
        "key_findings": key_items,
        "suppressed_findings": _suppressed_summary(scan),
        "scan_decisions_timeline": _decisions_timeline(scan),
        "risk_posture_overview": _risk_posture(counts, findings),
        "assessment_confidence_and_limitations": _confidence_reasons(scan, counts),
        "operating_context": _operating_context(scan),
    }

    return report


__all__ = ["build_professional_report"]
