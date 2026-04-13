"""
Finding Correlation Engine
Combines related findings into coherent risk stories.
"""

import uuid
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Any

from app.core.scanner import Finding, RiskLevel
from app.utils.logger import logger
from app.core.intelligence.context_analyzer import ContextAnalyzer
from app.core.intelligence.severity_engine import SeverityEngine
from app.core.intelligence.exploitation_readiness import ExploitationReadiness
from app.core.intelligence.pentester_thinking_engine import PentesterThinkingEngine


class CorrelationEngine:
    """Rule-driven correlation of findings into single risks."""

    def __init__(self):
        self.logger = logger.bind(component="CorrelationEngine")
        self.context_analyzer = ContextAnalyzer()
        self.severity_engine = SeverityEngine()
        self.exploitation_readiness = ExploitationReadiness()
        self.thinking_engine = PentesterThinkingEngine()

    def correlate(self, findings: List[Finding], target_url: str) -> Tuple[List[Dict[str, Any]], List[Finding]]:
        if not findings:
            return [], []

        scoped_findings = self._filter_in_scope(findings, target_url)
        if not scoped_findings:
            return [], []

        endpoint_map = self._group_by_endpoint(scoped_findings)
        tech_map = self._group_by_tech(scoped_findings)

        correlated: List[Dict[str, Any]] = []

        correlated.extend(self._rule_endpoint_bundle(endpoint_map))
        correlated.extend(self._rule_tech_bundle(tech_map))
        correlated.extend(self._rule_missing_header_chain(endpoint_map))

        # Deduplicate by correlated_findings set
        unique = {}
        for risk in correlated:
            key = tuple(sorted(risk.get("correlated_findings", []))) or risk.get("title")
            if key not in unique:
                unique[key] = risk

        correlated_risks = list(unique.values())

        # Attach correlation ids back to findings
        by_id = {f.id: f for f in scoped_findings}
        for risk in correlated_risks:
            for fid in risk.get("correlated_findings", []):
                f = by_id.get(fid)
                if f:
                    ids = getattr(f, "correlated_with", []) or []
                    ids.append(risk["id"])
                    f.correlated_with = list(set(ids))

        return correlated_risks, scoped_findings

    def build_report(self, correlated_risks: List[Dict[str, Any]], findings: List[Finding]) -> Dict[str, Any]:
        heatmap = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for risk in correlated_risks:
            lvl = risk.get("risk_level", "info").lower()
            if lvl in heatmap:
                heatmap[lvl] += 1
        for f in findings:
            lvl = f.risk_level.value.lower()
            if lvl in heatmap:
                heatmap[lvl] += 0  # keep counts separated for now

        top5 = sorted(
            correlated_risks,
            key=lambda r: (self._severity_weight(r.get("risk_level")), r.get("confidence_score", 0)),
            reverse=True
        )[:5]

        attacker_next_steps = []
        for risk in top5:
            attacker_next_steps.append(
                f"Next: {risk.get('attack_chain', ['Review'])[0]} then pivot to {risk.get('title')}"
            )

        return {
            "executive_summary": self._build_exec_summary(correlated_risks, findings),
            "risk_heatmap": heatmap,
            "top_5_critical": [r.get("title") for r in top5],
            "attacker_next_steps": attacker_next_steps,
        }

    def _filter_in_scope(self, findings: List[Finding], target_url: str) -> List[Finding]:
        parsed_target = urlparse(target_url)
        target_host = parsed_target.hostname
        scoped = []
        for f in findings:
            host = urlparse(f.affected_url).hostname
            if host and host == target_host:
                scoped.append(f)
            else:
                self.logger.info("Dropping out-of-scope finding", extra={"finding": f.title, "host": host})
        return scoped

    def _group_by_endpoint(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in findings:
            parsed = urlparse(f.affected_url)
            key = f"{parsed.hostname}{parsed.path}"
            groups.setdefault(key, []).append(f)
        return groups

    def _group_by_tech(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        groups: Dict[str, List[Finding]] = {}
        for f in findings:
            ev = f.evidence or {}
            tags = []
            for tag_key in ["server", "x_powered_by", "framework", "language", "favicon_sha1"]:
                val = ev.get(tag_key)
                if val:
                    tags.append(str(val).lower())
            for tag in tags:
                groups.setdefault(tag, []).append(f)
        return groups

    def _rule_endpoint_bundle(self, endpoint_map: Dict[str, List[Finding]]) -> List[Dict[str, Any]]:
        risks = []
        for key, flist in endpoint_map.items():
            categories = set([f.tool_name for f in flist])
            interesting = {"fingerprint", "headers", "ssl", "dir_brute"}
            if len(categories & interesting) < 2:
                continue
            risk_id = str(uuid.uuid4())
            correlated_ids = [f.id for f in flist]
            
            # Analyze context
            context = self.context_analyzer.analyze_finding_context(
                flist[0].affected_url,
                flist[0].evidence or {},
                flist
            )
            
            # Apply pentester thinking: what would a professional decide?
            thinking_decision = self.thinking_engine.evaluate(
                finding=flist[0],
                context=context,
                related_findings=flist[1:]
            )
            
            # Map thinking output to risk
            risk = {
                "id": risk_id,
                "title": "Endpoint surface risk",
                "single_risk_summary": f"Combined exposure on {key}",
                "risk_level": thinking_decision.severity.value,
                "base_severity": thinking_decision.severity.value,
                "severity_explanation": thinking_decision.reasoning,
                "confidence_score": thinking_decision.confidence,
                "attack_chain": thinking_decision.attack_chain or ["Enumerate endpoint", "Inspect headers/TLS"],
                "correlated_findings": correlated_ids,
                "validation_type": "needs_manual" if thinking_decision.decision.value == "STOP" else "needs_verification",
                "next_probe": thinking_decision.next_probe,
                "attacker_would_try": thinking_decision.reasoning,
                "false_positive_likelihood": self._min_fp_likelihood(flist),
                "exploitability_score": self._max_exploitability(flist),
                "context": {
                    "surface": thinking_decision.surface.value,
                    "business_value": thinking_decision.business_value.value,
                    **context
                },
                "decision": thinking_decision.decision.value,
                "stop_reason": thinking_decision.stop_reason,
                "why_not_exploited": thinking_decision.why_not_exploited,
            }
            risks.append(risk)
        return risks

    def _rule_tech_bundle(self, tech_map: Dict[str, List[Finding]]) -> List[Dict[str, Any]]:
        risks = []
        for tag, flist in tech_map.items():
            has_weak_tls = any("tls" in (f.title or "").lower() or "tls" in str(f.evidence).lower() for f in flist)
            has_dir = any("dir" in f.tool_name for f in flist)
            if not (has_weak_tls and has_dir):
                continue
            risk_id = str(uuid.uuid4())
            
            # Context analysis
            context = self.context_analyzer.analyze_finding_context(
                flist[0].affected_url,
                flist[0].evidence or {},
                flist
            )
            
            # Pentester thinking: evaluate the chain
            thinking_decision = self.thinking_engine.evaluate(
                finding=flist[0],
                context=context,
                related_findings=flist[1:]
            )
            
            risk = {
                "id": risk_id,
                "title": f"Tech stack exposed: {tag}",
                "single_risk_summary": "Stack disclosure plus exposed paths and weak transport",
                "risk_level": thinking_decision.severity.value,
                "base_severity": thinking_decision.severity.value,
                "severity_explanation": thinking_decision.reasoning,
                "confidence_score": thinking_decision.confidence,
                "attack_chain": thinking_decision.attack_chain or ["Fingerprint stack", "Probe exposed paths"],
                "correlated_findings": [f.id for f in flist],
                "validation_type": "auto_confirmed" if has_weak_tls else "needs_manual",
                "next_probe": thinking_decision.next_probe,
                "false_positive_likelihood": self._min_fp_likelihood(flist),
                "exploitability_score": self._max_exploitability(flist),
                "context": {
                    "surface": thinking_decision.surface.value,
                    "business_value": thinking_decision.business_value.value,
                    **context
                },
                "decision": thinking_decision.decision.value,
                "why_not_exploited": thinking_decision.why_not_exploited,
                "business_impact": self._explain_business_impact(context, "tech_stack"),
            }
            risks.append(risk)
        return risks

    def _rule_missing_header_chain(self, endpoint_map: Dict[str, List[Finding]]) -> List[Dict[str, Any]]:
        risks = []
        for key, flist in endpoint_map.items():
            missing = [f for f in flist if "missing" in f.title.lower() or "header" in f.title.lower()]
            if not missing:
                continue
            has_login = any("login" in f.affected_url.lower() or "admin" in f.affected_url.lower() for f in flist)
            if not has_login:
                continue
            risk_id = str(uuid.uuid4())
            
            # Context analysis for login/admin surface
            context = self.context_analyzer.analyze_finding_context(
                missing[0].affected_url,
                missing[0].evidence or {},
                missing
            )
            
            # Pentester thinking: admin/auth surface missing headers
            thinking_decision = self.thinking_engine.evaluate(
                finding=missing[0],
                context=context,
                related_findings=missing[1:]
            )
            
            risk = {
                "id": risk_id,
                "title": "Header hardening required on auth surface",
                "single_risk_summary": "Missing security headers on login/admin enables clickjacking/XSS chain",
                "risk_level": thinking_decision.severity.value,
                "base_severity": thinking_decision.severity.value,
                "severity_explanation": thinking_decision.reasoning,
                "confidence_score": thinking_decision.confidence,
                "attack_chain": thinking_decision.attack_chain or ["Load login page", "Exploit missing headers"],
                "correlated_findings": [f.id for f in missing],
                "validation_type": "needs_manual",
                "next_probe": thinking_decision.next_probe,
                "manual_checklist": [
                    "Capture login page response and headers",
                    "Confirm missing CSP/X-Frame-Options on auth endpoints",
                    "Test reflected input fields with benign payloads",
                ],
                "false_positive_likelihood": self._min_fp_likelihood(missing),
                "exploitability_score": self._max_exploitability(missing),
                "context": {
                    "surface": thinking_decision.surface.value,
                    "business_value": thinking_decision.business_value.value,
                    **context
                },
                "decision": thinking_decision.decision.value,
                "stop_reason": thinking_decision.stop_reason,
                "business_impact": self._explain_business_impact(context, "missing_headers"),
                "why_not_exploited": thinking_decision.why_not_exploited,
            }
            risks.append(risk)
        return risks

    def _aggregate_confidence(self, findings: List[Finding], bonus: float = 0.0) -> float:
        if not findings:
            return 0.0
        base = sum([f.confidence_score or 0.5 for f in findings]) / len(findings)
        return min(base + bonus, 1.0)

    def _min_fp_likelihood(self, findings: List[Finding]) -> float:
        vals = [f.false_positive_likelihood for f in findings if getattr(f, "false_positive_likelihood", None) is not None]
        return min(vals) if vals else 0.2

    def _max_exploitability(self, findings: List[Finding]) -> float:
        vals = [f.exploitability_score for f in findings if getattr(f, "exploitability_score", None) is not None]
        return max(vals) if vals else 0.6

    def _validation_type(self, findings: List[Finding]) -> str:
        auto_signals = [
            any("tls" in str(f.evidence).lower() for f in findings),
            any("status_code" in (f.evidence or {}) for f in findings),
        ]
        if any(auto_signals):
            return "auto_confirmed"
        return "needs_manual"

    def _elevate_severity(self, findings: List[Finding]) -> RiskLevel:
        high_surface = any("admin" in f.affected_url.lower() or "login" in f.affected_url.lower() for f in findings)
        weak_transport = any("tls" in f.title.lower() or "tls" in str(f.evidence).lower() for f in findings)
        missing_headers = any("header" in f.title.lower() for f in findings)
        if high_surface and (weak_transport or missing_headers):
            return RiskLevel.HIGH
        if weak_transport:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _severity_weight(self, risk_level: str) -> int:
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        return order.get((risk_level or "info").lower(), 1)

    def _explain_business_impact(self, context: Dict[str, Any], risk_type: str) -> str:
        """Explain why this matters from business perspective"""
        exposure = context.get("exposure")
        business_value = context.get("business_value")
        
        if risk_type == "tech_stack":
            if business_value == "critical":
                return "Stack disclosure on critical surface enables targeted attacks; adversaries can research known CVEs."
            else:
                return "Stack disclosure reduces attacker reconnaissance time; enables version-specific exploit research."
        
        elif risk_type == "missing_headers":
            if exposure == "admin_surface":
                return "Missing headers on admin surface enable credential theft via clickjacking; high impact to privileged accounts."
            elif exposure == "auth_required":
                return "Missing headers on auth surface enable session hijacking via XSS; compromise of user accounts."
            else:
                return "Missing headers on public surface enable phishing attacks; reputational risk."
        
        return "Security hardening recommended to reduce attack surface."
    
    def _build_exec_summary(self, correlated_risks: List[Dict[str, Any]], findings: List[Finding]) -> str:
        high = [r for r in correlated_risks if (r.get("risk_level", "").lower() in ["critical", "high"])]
        login_surface = [f for f in findings if "login" in f.affected_url.lower() or "admin" in f.affected_url.lower()]
        
        # Analyze attack surface
        surface_analysis = self.context_analyzer.analyze_attack_surface(findings)
        
        return (
            f"Identified {len(correlated_risks)} correlated risks; "
            f"{len(high)} are high/critical. Auth surface findings: {len(login_surface)}. "
            f"{surface_analysis.get('attack_surface_summary', '')}"
        )


__all__ = ["CorrelationEngine"]
