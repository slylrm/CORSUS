"""
Scan API Endpoints - Enhanced
Web sitesi tarama operasyonları
Cross-validation, false positive kontrolü, showcase mode support
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Request
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl, Field, validator
from datetime import datetime
from enum import Enum

from app.utils.logger import logger
from app.core.scanner import scanner_engine, ScanStatus as EngineScanStatus
from app.core.cross_validator import CrossValidator
from app.core.waf_detector import WAFDetector
from app.core.result_validator import ResultValidator
from app.core.showcase_mode import ShowcaseMode
from app.core.correlation.correlator import CorrelationEngine
from app.core.intelligence.professional_report_mode import build_professional_report


router = APIRouter()

# In-memory storage (geçici - production'da database kullanılacak)
scans_db = {}

# Initialize validators and detectors
cross_validator = CrossValidator()
waf_detector = WAFDetector()
result_validator = ResultValidator()
showcase_mode = ShowcaseMode()
correlation_engine = CorrelationEngine()


class ScanType(str, Enum):
    """Tarama tipleri"""
    QUICK = "quick"          # Hızlı tarama (5-10 dk)
    STANDARD = "standard"    # Standart tarama (30-60 dk)
    DEEP = "deep"           # Derin tarama (2-4 saat)
    CUSTOM = "custom"       # Özel yapılandırma


class ScanStatus(str, Enum):
    """Tarama durumları"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRequest(BaseModel):
    """Assessment başlatma isteği"""
    target_url: HttpUrl = Field(..., description="Değerlendirilecek hedef URL")
    scan_type: ScanType = Field(default=ScanType.QUICK, description="Değerlendirme tipi")
    tools: Optional[List[str]] = Field(default=None, description="Kullanılacak araçlar (boş ise hepsi)")
    domain_verification_token: Optional[str] = Field(default=None, description="Domain doğrulama token'ı")
    authorization_acknowledged: bool = Field(..., description="I confirm I am authorized to assess this target")
    scope_statement: str = Field(..., min_length=10, description="Explicit scope statement for this engagement")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target_url": "https://app.example.com",
                "scan_type": "quick",
                "tools": ["crawler", "headers"],
                "domain_verification_token": "weppen-assess-verify-abc123",
                "authorization_acknowledged": True,
                "scope_statement": "Assess the public app entrypoints at app.example.com"
            }
        }

    @validator("authorization_acknowledged")
    def must_acknowledge(cls, v):
        if not isinstance(v, bool) or v is not True:
            raise ValueError("Authorization acknowledgement must be boolean true")
        return v


class ScanResponse(BaseModel):
    """Scan başlatma yanıtı"""
    scan_id: str
    target_url: str
    status: ScanStatus
    created_at: datetime
    estimated_duration_minutes: int
    message: str
    authorization_acknowledged: bool
    scope_statement: str


class FindingResponseItem(BaseModel):
    """Finding response model"""
    id: str
    title: str
    description: str
    risk_level: str
    affected_url: str
    tool_name: str
    recommendation: str
    confidence_score: float
    verification_status: str
    sources: List[str]
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence_quality_score: Optional[float] = None
    false_positive_likelihood: Optional[float] = None
    exploitability_score: Optional[float] = None
    reproducibility_steps: Optional[List[str]] = None
    validation_type: Optional[str] = None
    correlated_with: Optional[List[str]] = None


class CorrelatedRiskItem(BaseModel):
    """Correlated risk model"""
    id: str
    title: str
    single_risk_summary: str
    risk_level: str
    base_severity: Optional[str] = None
    severity_explanation: Optional[str] = None
    confidence_score: float
    validation_type: str
    correlated_findings: List[str]
    attack_chain: List[str]
    next_probe: Optional[str] = None
    attacker_would_try: Optional[str] = None
    business_impact: Optional[str] = None
    what_blocked_exploitation: Optional[str] = None
    false_positive_likelihood: Optional[float] = None
    exploitability_score: Optional[float] = None
    manual_checklist: Optional[List[str]] = None
    context: Optional[Dict[str, Any]] = None


class ReportSummary(BaseModel):
    """Report-friendly summary"""
    executive_summary: str
    risk_heatmap: Dict[str, int]
    top_5_critical: List[str]
    attacker_next_steps: List[str]


class ScanStatusResponse(BaseModel):
    """Scan durum yanıtı - Enhanced"""
    scan_id: str
    target_url: str
    status: ScanStatus
    progress: int = Field(..., ge=0, le=100, description="Tamamlanma yüzdesi")
    current_phase: Optional[str] = None
    current_tool: Optional[str] = None
    findings_count: int = 0
    findings_validated: int = 0
    findings_needs_review: int = 0
    findings: List[FindingResponseItem] = []  # ✅ Findings list
    correlated_risks: List[CorrelatedRiskItem] = []
    report_summary: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    # ✅ WAF Detection fields
    waf_detected: bool = False
    waf_vendor: Optional[str] = None
    rate_limiting_detected: bool = False
    bot_protection_detected: bool = False
    authorization_acknowledged: bool = False
    scope_statement: Optional[str] = None


@router.post("/", response_model=ScanResponse, status_code=201)
@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    request: Request
):
    """
    Yeni bir güvenlik taraması başlat
    
    - **target_url**: Taranacak web sitesi (https://example.com)
    - **scan_type**: Tarama tipi (quick, standard, deep, custom)
    - **tools**: Kullanılacak araçlar listesi (opsiyonel)
    - **domain_verification_token**: Domain sahipliği doğrulama token'ı
    - **authorization_acknowledged**: Must be boolean true - confirms authorization to assess target
    - **scope_statement**: Explicit engagement scope (min 10 chars)
    
    Returns:
        Scan ID ve durum bilgisi with 201 Created status
        
    Raises:
        400: If authorization_acknowledged is not true
        422: If validation fails (invalid URL, missing fields, authorization is not boolean true)
    """
    
    target_url = str(scan_request.target_url)
    logger.info(f"[SCAN_REQUEST] target_url={target_url}, scan_type={scan_request.scan_type}, authorization={scan_request.authorization_acknowledged}, scope_len={len(scan_request.scope_statement)}")
    
    # DIAGNOSTIC: Log authorization details
    logger.debug(f"[AUTH_CHECK] authorization_acknowledged={repr(scan_request.authorization_acknowledged)}, type={type(scan_request.authorization_acknowledged).__name__}")
    
    # Check if showcase mode
    is_showcase = getattr(request.state, "should_mask_data", False)
    
    # If showcase mode, use controlled showcase findings instead of actual scanning
    if is_showcase or showcase_mode.should_use_demo_mode(target_url):
        logger.info(f"Showcase mode activated for: {target_url}")
        # Showcase findings will be used
    
    # Araçları belirle
    tools = scan_request.tools
    if not tools:
        # Tarama tipine göre default araçlar (pure async, no external deps)
        if scan_request.scan_type == ScanType.QUICK:
            tools = ["crawler", "fingerprint"]
        elif scan_request.scan_type == ScanType.STANDARD:
            tools = ["crawler", "dir_brute", "fingerprint", "basic", "headers", "ssl", "ports"]
        else:
            tools = ["crawler", "dir_brute", "fingerprint", "basic", "headers", "ssl", "ports"]
    
    # Authorization acknowledgement required
    if not scan_request.authorization_acknowledged:
        raise HTTPException(status_code=400, detail="Authorization acknowledgement is required to start an assessment")

    # Tarama oluştur
    try:
        scan = scanner_engine.create_scan(
            target_url=target_url,
            scan_type=scan_request.scan_type.value,
            tools=tools,
            authorization_acknowledged=scan_request.authorization_acknowledged,
            scope_statement=scan_request.scope_statement,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    
    # Background task olarak taramayı başlat
    scan_id = scan.scan_id  # ✅ Capture scan_id from outer scope
    async def run_scan_task():
        scan = None
        logger.info(f"[BG_TASK_START] scan_id={scan_id}, target={target_url}")
        try:
            scan = scanner_engine.get_scan(scan_id)  # ✅ Use captured scan_id
            if scan:
                logger.info(f"[BG_TASK_SCAN_FOUND] status={scan.status}")
            else:
                logger.error(f"[BG_TASK_SCAN_NOT_FOUND] scan_id={scan_id}")
            
            # Check showcase mode - gerçek scan yerine demo findings kullan
            showcase_result = showcase_mode.should_use_demo_mode(target_url)
            logger.info(f"[BG_TASK_SHOWCASE_CHECK] is_showcase={is_showcase}, should_demo={showcase_result}")
            if is_showcase or showcase_result:
                logger.info(f"[BG_TASK_SHOWCASE_ACTIVATED] Showcase mode: Using demo findings for {scan.scan_id}")
                scan.status = EngineScanStatus.RUNNING
                scan.started_at = datetime.now()
                
                # Demo findings'i al
                demo_findings = showcase_mode.get_demo_findings(target_url)
                
                # Finding'leri scanner's findings'e ekle
                from app.core.scanner import Finding
                for demo_data in demo_findings:
                    finding = Finding(
                        title=demo_data.title,
                        description=demo_data.description,
                        risk_level=demo_data.risk_level,
                        affected_url=demo_data.affected_url,
                        tool_name=demo_data.tool_name,
                        evidence=demo_data.evidence,
                        recommendation=demo_data.recommendation,
                        confidence_score=demo_data.confidence_score,
                        sources=demo_data.sources,
                        detection_method=demo_data.detection_method,
                    )
                    scan.findings.append(finding)
                
                scan.progress = 100
                scan.status = EngineScanStatus.COMPLETED
                scan.completed_at = datetime.now()
                logger.info(f"Showcase scan {scan.scan_id} completed with {len(scan.findings)} demo findings")
                return  # ← Prevent falling through to else block
            else:
                # Normal scan - tool wrappers'ı çalıştır
                # Tool classes mapping (pure Python async + optional external)
                from app.tools.discovery.builtin_scanner_wrapper import (
                    BasicInfoWrapper, SecurityHeadersWrapper, SSLScannerWrapper, PortScannerWrapper
                )
                from app.tools.discovery.crawler_async import AsyncCrawlerWrapper
                from app.tools.discovery.dir_bruteforce_async import DirBruteAsyncWrapper
                from app.tools.discovery.tech_fingerprint import TechFingerprintWrapper
                
                tool_classes = {
                    # Built-in async tools (no external binaries)
                    "crawler": AsyncCrawlerWrapper,
                    "dir_brute": DirBruteAsyncWrapper,
                    "fingerprint": TechFingerprintWrapper,
                    "basic": BasicInfoWrapper,
                    "headers": SecurityHeadersWrapper,
                    "ssl": SSLScannerWrapper,
                    "ports": PortScannerWrapper,
                }
                
                # Sadece kullanılacak tool'ları filtrele
                available_tools = {}
                for tool_name in scan.tools:
                    if tool_name in tool_classes:
                        available_tools[tool_name] = tool_classes[tool_name]
                
                if available_tools:
                    await scanner_engine.run_scan(scan.scan_id, available_tools)
                else:
                    logger.warning(f"No available tools for scan {scan.scan_id}")
                    scan.status = EngineScanStatus.FAILED
                    scan.error_message = "No available tools to run"
                    scan.completed_at = datetime.now()
                    
        except Exception as e:
            logger.error(f"Error running scan task: {e}", exc_info=True)
            # ✅ FAIL-SAFE: Background task exception scan'i FAILED yapmalı
            scan = scanner_engine.get_scan(scan_id)  # ✅ Use captured scan_id
            if scan:
                scan.status = EngineScanStatus.FAILED
                scan.error_message = f"Background task exception: {str(e)}"
                scan.completed_at = datetime.now()
        finally:
            # ✅ FINAL GARANTISI: Scan mutlaka finalize edilir
            scan = scanner_engine.get_scan(scan_id)  # ✅ Use captured scan_id
            if scan and not scan.completed_at:
                # Hala tamamlanmamışsa force complete
                if scan.status == EngineScanStatus.RUNNING:
                    scan.status = EngineScanStatus.FAILED
                    scan.error_message = "Scan finalized by background task cleanup"
                scan.completed_at = datetime.now()
                logger.warning(f"[BACKGROUND TASK CLEANUP] Forced completion of scan {scan.scan_id}")
    
    background_tasks.add_task(run_scan_task)
    
    # Tahmini süre hesaplama
    duration_map = {
        ScanType.QUICK: 5,
        ScanType.STANDARD: 10,
        ScanType.DEEP: 20,
        ScanType.CUSTOM: 15,
    }
    
    logger.info(f"Assessment created: {scan.scan_id} | authorization_acknowledged={scan_request.authorization_acknowledged}")
    
    return ScanResponse(
        scan_id=scan.scan_id,
        target_url=target_url,
        status=ScanStatus.PENDING,
        created_at=scan.created_at,
        estimated_duration_minutes=duration_map[scan_request.scan_type],
        message="Assessment initiated and will start shortly",
        authorization_acknowledged=scan_request.authorization_acknowledged,
        scope_statement=scan_request.scope_statement,
    )


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, request: Request):
    """
    Tarama durumunu sorgula
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Scan durumu ve ilerlemesi (showcase mode ile maskeleme yapılabilir)
    """
    
    scan = scanner_engine.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")
    
    # ✅ Cross-validate findings
    findings = scan.findings
    correlated_risks = scan.correlated_risks or []
    if findings and scan.status == "completed":
        findings = cross_validator.cross_validate_findings(findings)
        findings = cross_validator.validate_by_payload_matching(findings)
        
        # Apply result validator
        findings = result_validator.validate_findings(
            findings,
            waf_detected=scan.waf_detected if hasattr(scan, 'waf_detected') else False
        )
        
        # Correlate into risk stories
        correlated_risks, findings = correlation_engine.correlate(
            findings,
            target_url=scan.target_url,
        )
        scan.correlated_risks = correlated_risks
        scan.report_summary = build_professional_report(scan, correlated_risks, findings)
        scan.findings = findings
    
    # Count findings by validation status
    findings_validated = len([f for f in findings if hasattr(f, 'verification_status') and f.verification_status.value == "verified"])
    findings_needs_review = len([f for f in findings if hasattr(f, 'verification_status') and f.verification_status.value == "needs_manual_verification"])
    
    # ✅ Convert findings to response items
    findings_response = []
    for finding in findings:
        findings_response.append(FindingResponseItem(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            risk_level=finding.risk_level.value,
            affected_url=finding.affected_url,
            tool_name=finding.tool_name,
            recommendation=finding.recommendation,
            confidence_score=finding.confidence_score,
            verification_status=finding.verification_status.value if hasattr(finding, 'verification_status') else "unverified",
            sources=finding.sources,
            cwe_id=finding.cwe_id,
            cvss_score=finding.cvss_score,
            evidence_quality_score=getattr(finding, "evidence_quality_score", None),
            false_positive_likelihood=getattr(finding, "false_positive_likelihood", None),
            exploitability_score=getattr(finding, "exploitability_score", None),
            reproducibility_steps=getattr(finding, "reproducibility_steps", None),
            validation_type=getattr(finding, "validation_type", None),
            correlated_with=getattr(finding, "correlated_with", None),
        ))

    correlated_response: List[CorrelatedRiskItem] = []
    for risk in correlated_risks:
        correlated_response.append(CorrelatedRiskItem(
            id=risk.get("id"),
            title=risk.get("title"),
            single_risk_summary=risk.get("single_risk_summary"),
            risk_level=risk.get("risk_level"),
            base_severity=risk.get("base_severity"),
            severity_explanation=risk.get("severity_explanation"),
            confidence_score=risk.get("confidence_score", 0.0),
            validation_type=risk.get("validation_type", "needs_manual"),
            correlated_findings=risk.get("correlated_findings", []),
            attack_chain=risk.get("attack_chain", []),
            next_probe=risk.get("next_probe"),
            attacker_would_try=risk.get("attacker_would_try"),
            business_impact=risk.get("business_impact"),
            what_blocked_exploitation=risk.get("what_blocked_exploitation"),
            false_positive_likelihood=risk.get("false_positive_likelihood"),
            exploitability_score=risk.get("exploitability_score"),
            manual_checklist=risk.get("manual_checklist"),
            context=risk.get("context"),
        ))
    
    response = ScanStatusResponse(
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        status=ScanStatus[scan.status.upper()] if isinstance(scan.status, str) else scan.status,
        progress=scan.progress,
        current_phase=getattr(scan, 'current_phase', None),
        current_tool=scan.current_tool,
        findings_count=len(findings),
        findings_validated=findings_validated,
        findings_needs_review=findings_needs_review,
        findings=findings_response,  # ✅ Include findings
        correlated_risks=correlated_response,
        report_summary=scan.report_summary or None,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        waf_detected=getattr(scan, 'waf_detected', False),
        waf_vendor=getattr(scan, 'waf_vendor', None),
        rate_limiting_detected=getattr(scan, 'rate_limit_detected', False),
        bot_protection_detected=getattr(scan, 'bot_protection_detected', False),
        authorization_acknowledged=getattr(scan, 'authorization_acknowledged', False),
        scope_statement=getattr(scan, 'scope_statement', None),
    )
    
    # ✅ Apply showcase mode if enabled
    is_showcase = getattr(request.state, "should_mask_data", False)
    if is_showcase:
        response_dict = response.model_dump()
        response_dict = showcase_mode.mask_sensitive_data(response_dict)
        response_dict = showcase_mode.add_demo_watermark(response_dict)
        response = ScanStatusResponse(**response_dict)
    
    return response


@router.get("/", response_model=List[ScanStatusResponse])
async def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Status filter"),
    limit: int = Query(10, ge=1, le=100, description="Limit results"),
    offset: int = Query(0, ge=0, description="Offset")
):
    """
    Tüm taramaları listele
    
    Args:
        status: Duruma göre filtrele (opsiyonel)
        limit: Maksimum sonuç sayısı
        offset: Atlama miktarı
        
    Returns:
        Scan listesi
    """
    
    # TODO: Veritabanından scan listesini çek
    
    # Mock response
    return [
        ScanStatusResponse(
            scan_id="scan_1",
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            progress=100,
            findings_count=5,
            started_at=datetime.now(),
            completed_at=datetime.now(),
        )
    ]


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str):
    """
    Çalışan bir taramayı iptal et
    
    Args:
        scan_id: Scan ID
    """
    
    logger.info(f"Cancelling scan: {scan_id}")
    
    # TODO: Celery task'ı revoke et
    # TODO: Veritabanında status'u CANCELLED yap
    
    return {"message": "Scan cancelled"}


@router.post("/{scan_id}/retry", response_model=ScanResponse)
async def retry_scan(scan_id: str):
    """
    Başarısız olan bir taramayı tekrar dene
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Yeni scan bilgisi
    """
    
    logger.info(f"Retrying scan: {scan_id}")
    
    # TODO: Önceki scan'i kontrol et
    # TODO: Yeni scan başlat
    
    raise HTTPException(status_code=501, detail="Not implemented yet")
