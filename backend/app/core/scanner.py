"""
Core Scanner Engine - Refactored
Tool Orchestration Engine

Tüm pentest araçlarını orkestre eder ve sonuçları standart Finding modeline dönüştürür

Sorumluluklar:
- Tool wrapper'larını sırayla çalıştırma
- Timeout ve hata yönetimi
- Sonuçları Finding modeline dönüştürme
- Tarama yaşam döngüsü yönetimi
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Type, Tuple, Any
from enum import Enum
import time
from urllib.parse import urlparse
from contextlib import contextmanager

from app.utils.logger import logger
from app.tools.base import BaseToolWrapper, ToolResult, RiskLevel
from app.core.intelligence.context_analyzer import ContextAnalyzer
from app.core.intelligence.pentester_thinking_engine import (
    DecisionType,
    PentesterThinkingEngine,
)
from app.core.intelligence.scan_thinking_engine import (
    ScanDecisionType,
    ScanThinkingEngine,
)
from app.core.intelligence.operating_mode import OperatingMode


class ScanStatus(str, Enum):
    """Tarama durumu"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class VerificationStatus(str, Enum):
    """Finding doğrulama durumu"""
    UNVERIFIED = "unverified"
    NEEDS_MANUAL = "needs_manual_verification"
    VERIFIED = "verified"


class OperatingModeViolation(RuntimeError):
    """Raised when a tool attempts an action outside the operating mode."""


class Finding:
    """
    Standartlaştırılmış Güvenlik Bulgusı
    Tüm tool wrapper'larından gelen sonuçları normalize eder
    """
    def __init__(
        self,
        title: str,
        description: str,
        risk_level: RiskLevel,
        affected_url: str,
        tool_name: str,
        evidence: Dict = None,
        recommendation: str = "",
        cwe_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        confidence_score: float = 1.0,
        sources: List[str] = None,
        detection_method: str = "automated",
        evidence_quality_score: Optional[float] = None,
        false_positive_likelihood: Optional[float] = None,
        exploitability_score: Optional[float] = None,
        reproducibility_steps: Optional[List[str]] = None,
        validation_type: Optional[str] = None,
        correlated_with: Optional[List[str]] = None,
    ):
        self.id = str(uuid.uuid4())
        self.title = title
        self.description = description
        self.risk_level = risk_level if isinstance(risk_level, RiskLevel) else RiskLevel(risk_level)
        self.raw_risk_level = self.risk_level
        self.affected_url = affected_url
        self.tool_name = tool_name
        self.evidence = evidence or {}
        self.recommendation = recommendation
        self.cwe_id = cwe_id
        self.cvss_score = cvss_score
        self.found_at = datetime.now()
        
        # Confidence & Verification
        self.confidence_score: float = confidence_score  # 0.0 - 1.0
        self.verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
        self.sources: List[str] = sources or [tool_name]
        self.detection_method: str = detection_method
        self.evidence_quality_score: Optional[float] = evidence_quality_score
        self.false_positive_likelihood: Optional[float] = false_positive_likelihood
        self.exploitability_score: Optional[float] = exploitability_score
        self.reproducibility_steps: Optional[List[str]] = reproducibility_steps
        self.validation_type: Optional[str] = validation_type
        self.correlated_with: List[str] = correlated_with or []
        self.decision: Optional[str] = None
        self.decision_reason: Optional[str] = None
        self.attack_chain: Optional[List[str]] = None
        self.next_probe: Optional[str] = None
        self.why_not_exploited: Optional[str] = None
        self.stop_reason: Optional[str] = None
        self.business_value: Optional[str] = None
        self.surface: Optional[str] = None
        self.decision_confidence: Optional[float] = None
        self.context_snapshot: Optional[Dict[str, Any]] = None
        self.suppressed: bool = False
        self.action_taken: Optional[str] = None

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "affected_url": self.affected_url,
            "tool_name": self.tool_name,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "found_at": self.found_at.isoformat(),
            "confidence_score": self.confidence_score,
            "verification_status": self.verification_status.value,
            "sources": self.sources,
            "detection_method": self.detection_method,
            "evidence_quality_score": self.evidence_quality_score,
            "false_positive_likelihood": self.false_positive_likelihood,
            "exploitability_score": self.exploitability_score,
            "reproducibility_steps": self.reproducibility_steps,
            "validation_type": self.validation_type,
            "correlated_with": self.correlated_with,
            "raw_risk_level": self.raw_risk_level.value if self.raw_risk_level else None,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "attack_chain": self.attack_chain,
            "next_probe": self.next_probe,
            "why_not_exploited": self.why_not_exploited,
            "stop_reason": self.stop_reason,
            "business_value": self.business_value,
            "surface": self.surface,
            "decision_confidence": self.decision_confidence,
            "context_snapshot": self.context_snapshot,
            "suppressed": self.suppressed,
            "action_taken": self.action_taken,
        }


class Scan:
    """Tarama işlemini temsil eder"""
    def __init__(self, target_url: str, scan_type: str, tools: List[str] = None,
                 authorization_acknowledged: bool = False, scope_statement: Optional[str] = None,
                 operating_mode: OperatingMode = OperatingMode.SAFE_READ_ONLY):
        self.scan_id = str(uuid.uuid4())
        self.target_url = target_url
        self.scan_type = scan_type
        self.tools = tools or []
        self.status = ScanStatus.PENDING
        self.progress = 0
        self.current_tool = None
        self.current_phase: Optional[str] = None
        self.findings: List[Finding] = []
        self.tool_results: Dict[str, ToolResult] = {}  # Her tool'un sonuçlarını sakla
        self.correlated_risks: List[Dict[str, Any]] = []
        self.report_summary: Dict[str, Any] = {}
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.total_tools = len(self.tools) if self.tools else 0
        self.tools_completed = 0
        self.tool_errors: Dict[str, str] = {}  # Tool hatalarını takip et
        self.stopped_surfaces: set[str] = set()
        self.suppressed_findings: List[Finding] = []
        self.surface_counts: Dict[str, int] = {}
        self.severity_counts: Dict[str, int] = {}
        self.stop_events: List[Dict[str, Any]] = []
        self.hygiene_counts: Dict[Any, int] = {}
        self.total_processed: int = 0
        self.chains_observed: int = 0
        self.scan_decisions: List[Dict[str, Any]] = []
        self.depth_reduced: bool = False
        self.escalated: bool = False
        self.authorization_acknowledged: bool = authorization_acknowledged
        self.scope_statement: Optional[str] = scope_statement
        self.operating_mode: OperatingMode = operating_mode
        self.target_key: str = target_url.lower()

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "status": self.status.value,
            "progress": self.progress,
            "current_tool": self.current_tool,
            "current_phase": self.current_phase,
            "findings_count": len(self.findings),
            "correlated_risks_count": len(self.correlated_risks),
            "total_tools": self.total_tools,
            "tools_completed": self.tools_completed,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "report_summary": self.report_summary,
            "authorization_acknowledged": self.authorization_acknowledged,
            "scope_statement": self.scope_statement,
            "operating_mode": self.operating_mode.value if self.operating_mode else None,
        }


class ToolRunner:
    """
    Tool wrapper'larını çalıştıran ve sonuçlarını işleyen helper sınıf
    
    Sorumluluklar:
    - Tool instance oluşturma
    - Timeout yönetimi
    - Hata yönetimi
    - Sonuçları Finding'e dönüştürme
    """
    
    def __init__(self, timeout: int = 300, operating_mode: OperatingMode = OperatingMode.SAFE_READ_ONLY):
        """
        Initialize ToolRunner
        
        Args:
            timeout: Tool execution timeout in seconds
        """
        self.timeout = timeout
        self.logger = logger.bind(component="ToolRunner")
        self.operating_mode = operating_mode
    
    async def run_tool(
        self,
        tool_class: Type[BaseToolWrapper],
        target: str,
        options: Optional[Dict] = None
    ) -> Tuple[bool, List[Finding], Optional[str]]:
        """
        Tool wrapper'ı çalıştır ve sonuçları işle
        
        Args:
            tool_class: BaseToolWrapper inherit eden tool sınıfı
            target: Hedef URL/domain
            options: Tool-specific options
            
        Returns:
            (success: bool, findings: List[Finding], error: Optional[str])
        """
        tool_name = tool_class.name if hasattr(tool_class, 'name') else tool_class.__name__
        findings = []
        
        try:
            self.logger.info(f"[TOOL RUNNER] Starting {tool_name} with timeout={self.timeout}s")
            
            # Tool instance oluştur
            tool_instance = tool_class()
            if hasattr(tool_instance, "set_operating_mode"):
                try:
                    tool_instance.set_operating_mode(self.operating_mode)
                except Exception:
                    self.logger.debug("Operating mode setter not applied", exc_info=False)
            
            # ✅ HARD TIMEOUT: Tool mutlaka sonlanır
            # Timeout aşılırsa exception fırlatılır, tool durdurulur
            result = await asyncio.wait_for(
                self._execute_tool_async(tool_instance, target, options),
                timeout=self.timeout
            )
            
            # Sonuçları Finding'e dönüştür
            findings = self._convert_to_findings(result)
            
            self.logger.info(
                f"[TOOL RUNNER] {tool_name} completed - Findings: {len(findings)}"
            )
            
            return True, findings, None
            
        except asyncio.TimeoutError:
            # ✅ TIMEOUT: Tool takıldı, scan devam etmeli
            error_msg = f"TIMEOUT after {self.timeout}s"
            self.logger.error(f"[TOOL RUNNER] {tool_name} {error_msg}")
            return False, [], error_msg
            
        except OperatingModeViolation as e:
            error_msg = f"OPERATING_MODE_VIOLATION: {str(e)}"
            self.logger.error(f"[TOOL RUNNER] {tool_name} {error_msg}")
            return False, [], error_msg

        except Exception as e:
            # ✅ EXCEPTION: Tool hata verdi, scan devam etmeli
            error_msg = f"Exception: {str(e)}"
            self.logger.error(f"[TOOL RUNNER] {tool_name} {error_msg}", exc_info=True)
            return False, [], error_msg
    
    async def _execute_tool_async(
        self,
        tool_instance: BaseToolWrapper,
        target: str,
        options: Optional[Dict]
    ) -> ToolResult:
        """
        Tool'u async olarak çalıştır (async/sync metodları otomatik algıla)
        """
        import inspect
        
        # Tool.run() metodunun async olup olmadığını kontrol et
        guard_context = self._operating_mode_guard()
        with guard_context:
            if inspect.iscoroutinefunction(tool_instance.run):
                # Async tool - direkt await et
                result = await tool_instance.run(target, options)
            else:
                # Sync tool - executor'da çalıştır
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: tool_instance.run(target, options)
                )
        
        return result

    @contextmanager
    def _operating_mode_guard(self):
        """Enforce SAFE_READ_ONLY by monkey patching HTTP clients."""
        if self.operating_mode != OperatingMode.SAFE_READ_ONLY:
            yield
            return

        try:
            import requests
            import httpx
        except Exception:
            # If libs missing, still enforce via guard on known attributes
            requests = None
            httpx = None

        original_requests = requests.Session.request if requests else None
        original_httpx = httpx.AsyncClient.request if httpx else None

        def _guarded_request(self_or_cls, method, url, *args, **kwargs):  # type: ignore
            if method and method.upper() not in ["GET", "HEAD", "OPTIONS"]:
                raise OperatingModeViolation(f"HTTP method {method} blocked in SAFE_READ_ONLY mode")
            return original_requests(self_or_cls, method, url, *args, **kwargs)

        async def _guarded_request_async(self_or_cls, method, url, *args, **kwargs):  # type: ignore
            if method and method.upper() not in ["GET", "HEAD", "OPTIONS"]:
                raise OperatingModeViolation(f"HTTP method {method} blocked in SAFE_READ_ONLY mode")
            return await original_httpx(self_or_cls, method, url, *args, **kwargs)

        try:
            if requests:
                requests.Session.request = _guarded_request  # type: ignore
            if httpx:
                httpx.AsyncClient.request = _guarded_request_async  # type: ignore
            yield
        finally:
            if requests and original_requests:
                requests.Session.request = original_requests  # type: ignore
            if httpx and original_httpx:
                httpx.AsyncClient.request = original_httpx  # type: ignore
    
    def _convert_to_findings(self, tool_result: ToolResult) -> List[Finding]:
        """
        ToolResult'ı Finding listesine dönüştür
        
        Args:
            tool_result: Tool'dan gelen ToolResult
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if not tool_result.success:
            self.logger.warning(
                f"Tool {tool_result.tool_name} was not successful. "
                f"Errors: {tool_result.errors}"
            )
            return findings
        
        # Tool'un bulduğu her finding'i standardize et
        for finding_data in tool_result.findings:
            try:
                # ToolResult'taki findings Dict format
                finding = Finding(
                    title=finding_data.get("title", "Unknown Finding"),
                    description=finding_data.get("description", ""),
                    risk_level=RiskLevel(finding_data.get("risk_level", "medium")),
                    affected_url=finding_data.get("affected_url", tool_result.target),
                    tool_name=tool_result.tool_name,
                    evidence=finding_data.get("evidence", {}),
                    recommendation=finding_data.get("recommendation", ""),
                    cwe_id=finding_data.get("cwe_id"),
                    cvss_score=finding_data.get("cvss_score"),
                    confidence_score=finding_data.get("confidence_score", 0.8),
                    sources=[tool_result.tool_name],
                    detection_method=finding_data.get("detection_method", "automated"),
                    evidence_quality_score=finding_data.get("evidence_quality_score"),
                    false_positive_likelihood=finding_data.get("false_positive_likelihood"),
                    exploitability_score=finding_data.get("exploitability_score"),
                    reproducibility_steps=finding_data.get("reproducibility_steps"),
                    validation_type=finding_data.get("validation_type"),
                )

                # Optional verification status override (default UNVERIFIED)
                verification_status = finding_data.get("verification_status")
                if verification_status:
                    try:
                        finding.verification_status = VerificationStatus(verification_status)
                    except Exception:
                        self.logger.debug(
                            "Invalid verification_status provided; using default",
                            extra={"verification_status": verification_status},
                        )
                findings.append(finding)
                
            except Exception as e:
                self.logger.warning(
                    f"Error converting finding from {tool_result.tool_name}: {e}"
                )
                continue
        
        return findings


class ScannerEngine:
    """
    Tarama motorunu yönetir - Tool Orchestration
    
    Sorumluluklar:
    - Tarama yaşam döngüsü yönetimi
    - Tool wrapper'larını sırayla çalıştırma
    - Sonuçları toplama
    - Progress tracking
    """
    
    def __init__(self, tool_timeout: int = 300, operating_mode: OperatingMode = OperatingMode.SAFE_READ_ONLY):
        """
        Initialize ScannerEngine
        
        Args:
            tool_timeout: Timeout for each tool in seconds
        """
        self.active_scans: Dict[str, Scan] = {}
        self.operating_mode = operating_mode
        self.tool_runner = ToolRunner(timeout=tool_timeout, operating_mode=operating_mode)
        self.logger = logger.bind(component="ScannerEngine")
        self.context_analyzer = ContextAnalyzer()
        self.thinking_engine = PentesterThinkingEngine()
        self.scan_thinking_engine = ScanThinkingEngine()

    def _surface_key(self, finding: Finding) -> str:
        parsed = urlparse(finding.affected_url)
        path = parsed.path or "/"
        top_segment = path.split("/")[1] if "/" in path and len(path.split("/")) > 1 else path or "/"
        host = parsed.hostname or ""
        return f"{host}/{top_segment}"

    def _collect_related_findings(self, scan: Scan, finding: Finding) -> List[Finding]:
        surface_key = self._surface_key(finding)
        return [f for f in scan.findings if self._surface_key(f) == surface_key]

    def _apply_pentester_decision(
        self,
        finding: Finding,
        decision,
        context: Dict[str, Any],
    ) -> None:
        finding.raw_risk_level = finding.raw_risk_level if hasattr(finding, "raw_risk_level") else finding.risk_level
        finding.risk_level = RiskLevel(decision.severity.value)
        finding.decision = decision.decision.value
        finding.decision_reason = decision.reasoning
        finding.attack_chain = decision.attack_chain
        finding.next_probe = decision.next_probe
        finding.why_not_exploited = decision.why_not_exploited
        finding.stop_reason = decision.stop_reason
        finding.business_value = decision.business_value.value
        finding.surface = decision.surface.value
        finding.decision_confidence = decision.confidence
        finding.context_snapshot = context  # type: ignore[attr-defined]

    def _risk_weight(self, risk_level: RiskLevel) -> int:
        order = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 1,
        }
        return order.get(risk_level, 1)

    def _find_existing(self, scan: Scan, finding: Finding) -> Optional[Finding]:
        target_key = (finding.title.lower(), self._surface_key(finding))
        for existing in scan.findings:
            if (existing.title.lower(), self._surface_key(existing)) == target_key:
                return existing
        return None

    def _merge_findings(self, existing: Finding, new: Finding) -> None:
        existing.sources = list(set((existing.sources or []) + (new.sources or [])))
        if isinstance(existing.evidence, dict) and isinstance(new.evidence, dict):
            existing.evidence.update({f"evidence_from_{new.tool_name}": new.evidence})
        if self._risk_weight(new.risk_level) > self._risk_weight(existing.risk_level):
            existing.risk_level = new.risk_level
            existing.decision_reason = new.decision_reason
            existing.attack_chain = new.attack_chain or existing.attack_chain
            existing.decision_confidence = new.decision_confidence or existing.decision_confidence
            existing.business_value = new.business_value or existing.business_value
            existing.surface = new.surface or existing.surface
        existing.action_taken = "merged"

    def _process_with_thinking_engine(self, scan: Scan, findings: List[Finding]) -> List[Finding]:
        processed: List[Finding] = []

        for finding in findings:
            surface_key = self._surface_key(finding)

            if surface_key in scan.stopped_surfaces:
                finding.suppressed = True
                finding.action_taken = "suppressed_surface_stopped"
                scan.suppressed_findings.append(finding)
                self.logger.info("Skipping finding on stopped surface", extra={"surface": surface_key, "title": finding.title})
                continue

            related = self._collect_related_findings(scan, finding)
            context = self.context_analyzer.analyze_finding_context(
                finding.affected_url,
                finding.evidence or {},
                related,
            )
            decision = self.thinking_engine.evaluate(
                finding=finding,
                context=context,
                related_findings=related,
            )

            self._apply_pentester_decision(finding, decision, context)

            if decision.decision == DecisionType.STOP:
                scan.stopped_surfaces.add(surface_key)
                finding.suppressed = True
                finding.action_taken = "suppressed_stop_surface"
                scan.suppressed_findings.append(finding)
                self.logger.info("STOP decision: halting further scanning on surface", extra={"surface": surface_key, "reason": decision.stop_reason})
                continue

            existing = self._find_existing(scan, finding)
            if existing:
                self._merge_findings(existing, finding)
                self.logger.info("Merged finding into existing risk", extra={"title": finding.title, "surface": surface_key})
                continue

            finding.action_taken = "stored"
            processed.append(finding)

            # Scan-level thinking engine
            scan_decision = self.scan_thinking_engine.observe(scan, finding)
            scan.scan_decisions.append({
                "decision": scan_decision.decision.value,
                "reason": scan_decision.reason,
                "surface": scan_decision.surface,
                "after_finding": finding.id,
            })

            if scan_decision.decision == ScanDecisionType.STOP_SCAN:
                scan.status = ScanStatus.COMPLETED
                scan.error_message = scan_decision.reason
                self.logger.info("Scan-level STOP applied", extra={"reason": scan_decision.reason})
                break

            if scan_decision.decision == ScanDecisionType.REDUCE_DEPTH:
                scan.depth_reduced = True
                self.logger.info("Scan depth reduced due to hygiene cluster", extra={"surface": scan_decision.surface})

            if scan_decision.decision == ScanDecisionType.ESCALATE:
                scan.escalated = True
                self.logger.info("Scan escalated due to narrative/chain", extra={"surface": scan_decision.surface})

        return processed
    
    def _normalize_target(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        return (parsed.hostname or target_url).lower()

    def _has_active_scan_for_target(self, target_key: str) -> bool:
        for s in self.active_scans.values():
            if getattr(s, "target_key", "") == target_key and s.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
                return True
        return False

    def create_scan(
        self,
        target_url: str,
        scan_type: str,
        tools: List[str] = None,
        authorization_acknowledged: bool = False,
        scope_statement: Optional[str] = None,
    ) -> Scan:
        """
        Yeni bir tarama oluştur
        
        Args:
            target_url: Taranacak hedef URL
            scan_type: Tarama tipi (basic, full, vuln, etc.)
            tools: Çalıştırılacak tool'lar
            authorization_acknowledged: Yetki onayı
            scope_statement: Açık kapsam ifadesi
            
        Returns:
            Scan object
        """
        target_key = self._normalize_target(target_url)
        if self._has_active_scan_for_target(target_key):
            raise ValueError("Only one active assessment per target is allowed at a time")

        scan = Scan(
            target_url,
            scan_type,
            tools,
            authorization_acknowledged=authorization_acknowledged,
            scope_statement=scope_statement,
            operating_mode=self.operating_mode,
        )
        scan.target_key = target_key
        self.active_scans[scan.scan_id] = scan
        self.logger.info(f"Created scan {scan.scan_id} for {target_url}")
        return scan
    
    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Taramayı ID ile getir"""
        return self.active_scans.get(scan_id)
    
    async def run_scan(
        self,
        scan_id: str,
        tool_classes: Dict[str, Type[BaseToolWrapper]]
    ):
        """
        Taramayı çalıştır - Sırayla tool'ları çalıştır
        
        Args:
            scan_id: Çalıştırılacak scan ID
            tool_classes: Tool adı -> Tool sınıfı mapping
                         Örn: {"nmap": NmapWrapper, "sqlmap": SQLMapWrapper}
        """
        scan = self.get_scan(scan_id)
        if not scan:
            self.logger.error(f"Scan {scan_id} not found")
            return
        
        scan_completed_successfully = False
        total_tools = len(scan.tools) if scan.tools else 0
        tool_phase_map = {
            "crawler": "recon",
            "dir_brute": "recon",
            "fingerprint": "fingerprint",
            "basic": "recon",
            "headers": "recon",
            "ssl": "transport",
            "ports": "network",
        }
        
        try:
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now()
            self.logger.info(f"[SCAN START] {scan_id} for {scan.target_url} with {len(scan.tools)} tools")
            
            # Tool'ları sırayla çalıştır
            for idx, tool_name in enumerate(scan.tools):
                if scan.status != ScanStatus.RUNNING:
                    self.logger.info(f"[SCAN STOPPED] {scan_id} was stopped by user")
                    break
                
                # Progress güncelle
                scan.current_tool = tool_name
                scan.current_phase = tool_phase_map.get(tool_name, "execution")
                scan.progress = int((scan.tools_completed / total_tools) * 100) if total_tools else 0
                
                self.logger.info(
                    f"[TOOL START] {tool_name} ({idx + 1}/{len(scan.tools)}) - Progress: {scan.progress}%"
                )
                
                # Tool sınıfını bul
                tool_class = tool_classes.get(tool_name)
                if not tool_class:
                    error_msg = f"Tool class not found: {tool_name}"
                    self.logger.error(f"[TOOL ERROR] {tool_name} - {error_msg}")
                    scan.tool_errors[tool_name] = error_msg
                    scan.tools_completed += 1
                    continue
                
                # Tool'u çalıştır
                try:
                    success, findings, error = await self.tool_runner.run_tool(
                        tool_class,
                        target=scan.target_url,
                        options={"scan_type": scan.scan_type}
                    )
                    
                    # Sonuçları kaydet
                    scan.tools_completed += 1
                    
                    if success:
                        evaluated_findings = self._process_with_thinking_engine(scan, findings)
                        scan.findings.extend(evaluated_findings)
                        self.logger.info(
                            f"[TOOL END] {tool_name} - SUCCESS - Processed {len(evaluated_findings)} findings"
                        )
                    else:
                        if error:
                            scan.tool_errors[tool_name] = error
                            if "OPERATING_MODE_VIOLATION" in error:
                                scan.status = ScanStatus.COMPLETED
                                scan.error_message = error
                                self.logger.error("Operating mode violation triggered STOP_SCAN", extra={"tool": tool_name, "error": error})
                                break
                        self.logger.warning(f"[TOOL FAIL] {tool_name} - {error}")
                        
                except Exception as tool_exc:
                    # Tool hatası scan'i durdurmamalı
                    error_msg = f"Tool exception: {str(tool_exc)}"
                    scan.tool_errors[tool_name] = error_msg
                    scan.tools_completed += 1
                    self.logger.error(f"[TOOL EXCEPTION] {tool_name} - {error_msg}", exc_info=True)
                
                # Tool sonrası ilerleme güncelle
                scan.progress = int((scan.tools_completed / total_tools) * 100) if total_tools else 100
                scan.current_phase = None

                # Diğer tool'lar için yer ver (asyncio event loop)
                await asyncio.sleep(0.1)
            
            # Scan başarılı tamamlandı
            scan_completed_successfully = True
            self.logger.info(
                f"[SCAN COMPLETE] {scan_id} - "
                f"Tools: {scan.tools_completed}/{len(scan.tools)}, "
                f"Findings: {len(scan.findings)}, "
                f"Errors: {len(scan.tool_errors)}"
            )
            
        except Exception as e:
            # Kritik hata - scan başarısız
            scan.error_message = str(e)
            self.logger.error(f"[SCAN EXCEPTION] {scan_id} - {e}", exc_info=True)
            
        finally:
            # ✅ GARANTI: Scan mutlaka finalize edilir
            # Hiçbir koşulda RUNNING state'inde kalmaz
            
            if scan_completed_successfully and scan.status == ScanStatus.RUNNING:
                # Normal tamamlanma
                scan.status = ScanStatus.COMPLETED
                scan.progress = 100
            elif scan.status == ScanStatus.RUNNING:
                # Hata veya beklenmeyen durum - FAILED yap
                scan.status = ScanStatus.FAILED
                if not scan.error_message:
                    scan.error_message = "Scan failed to complete normally"
            
            # Tamamlanma zamanını set et
            scan.completed_at = datetime.now()
            
            # Final durum log
            self.logger.info(
                f"[SCAN FINALIZED] {scan_id} - "
                f"Status: {scan.status.value}, "
                f"Duration: {(scan.completed_at - scan.started_at).total_seconds():.1f}s, "
                f"Findings: {len(scan.findings)}, "
                f"Suppressed: {len(scan.suppressed_findings)}"
            )
    
    def stop_scan(self, scan_id: str):
        """Taramayı durdur"""
        scan = self.get_scan(scan_id)
        if scan and scan.status == ScanStatus.RUNNING:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Scan stopped by user"
            self.logger.info(f"Scan {scan_id} stopped")
    
    def get_findings(self, scan_id: str) -> List[Finding]:
        """Scan'ın bulgularını getir"""
        scan = self.get_scan(scan_id)
        return scan.findings if scan else []


# Global scanner instance
scanner_engine = ScannerEngine()
