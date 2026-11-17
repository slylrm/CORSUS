"""
Scan API Endpoints - Enhanced
Web sitesi tarama operasyonları
Cross-validation, false positive kontrolü, showcase mode support
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Request, Response
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, HttpUrl, Field, validator
from datetime import datetime
from enum import Enum
import json
from urllib.parse import urlparse

from app.utils.logger import logger
from app.config import settings
from app.core.scanner import scanner_engine, ScanStatus as EngineScanStatus
from app.core.cross_validator import CrossValidator
from app.core.waf_detector import WAFDetector
from app.core.result_validator import ResultValidator
from app.core.showcase_mode import ShowcaseMode
from app.core.correlation.correlator import CorrelationEngine
from app.core.intelligence.professional_report_mode import build_professional_report
from app.core.persistence import (
    get_findings_for_scan,
    get_scan_record,
    get_verification_token,
    list_scan_records,
    mark_scan_cancelled,
    persist_scan_findings,
    upsert_scan_state,
)
from app.tools.registry import (
    build_tool_options,
    canonical_tool_name,
    filter_installed_tool_names,
    get_default_tool_names,
    get_tool_plan,
)


router = APIRouter()

# In-memory storage (geçici - production'da database kullanılacak)
scans_db = {}

# Initialize validators and detectors
cross_validator = CrossValidator()
waf_detector = WAFDetector()
result_validator = ResultValidator()
showcase_mode = ShowcaseMode()
correlation_engine = CorrelationEngine()


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _is_local_target(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    lowered = hostname.lower()
    if lowered in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return True
    return lowered.endswith(".local")


def _get_owner_id(request: Request) -> Optional[str]:
    return getattr(request.state, "owner_id", None)


def _ensure_owner_access(owner_id: Optional[str], scan_or_record: Any, scan_id: str) -> None:
    if not owner_id:
        return
    if isinstance(scan_or_record, dict):
        if scan_or_record.get("owner_id") != owner_id:
            raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")
    else:
        if getattr(scan_or_record, "owner_id", None) != owner_id:
            raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")


def _normalize_host(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def _host_in_list(hostname: str, entries: List[str]) -> bool:
    host = _normalize_host(hostname)
    for entry in entries or []:
        normalized = _normalize_host(str(entry))
        if not normalized:
            continue
        if host == normalized or host.endswith(f".{normalized}"):
            return True
    return False


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
    evidence: Dict[str, Any] = Field(default_factory=dict)
    detection_method: Optional[str] = None
    found_at: Optional[datetime] = None
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


def _select_primary_tool_error(scan: Any) -> tuple[Optional[str], Optional[str]]:
    tool_errors = getattr(scan, "tool_errors", {}) or {}
    if not tool_errors:
        return getattr(scan, "current_tool", None), getattr(scan, "error_message", None)

    priority_markers = [
        "too many file descriptors",
        "select()",
        "timeout",
        "timed out",
        "not installed",
        "tool class not found",
        "operating_mode_violation",
    ]

    for marker in priority_markers:
        for tool_name, error_text in tool_errors.items():
            lowered = str(error_text or "").lower()
            if marker in lowered:
                return tool_name, str(error_text)

    tool_name, error_text = next(iter(tool_errors.items()))
    return tool_name, str(error_text)


def _classify_failure_details(
    *,
    raw_error: str,
    tool_name: Optional[str],
    stage: Optional[str],
) -> Dict[str, Optional[str]]:
    lowered = (raw_error or "").lower()

    if "too many file descriptors" in lowered or ("select()" in lowered and "descriptor" in lowered):
        return {
            "error_type": "socket_limit",
            "error_tool": tool_name,
            "error_stage": stage,
            "technical_reason": "Sistemde acik socket/file descriptor limiti asildi.",
            "error_hint": "Eszamanlilik dusurulmeli ve taramalar sirali calistirilmali.",
        }

    if "timeout" in lowered or "timed out" in lowered:
        return {
            "error_type": "timeout",
            "error_tool": tool_name,
            "error_stage": stage,
            "technical_reason": "Ag istegi veya arac calismasi zaman asimina ugradi.",
            "error_hint": "Hedef ulasilabilirligini kontrol edin ve timeout degerini artirin.",
        }

    if "not installed" in lowered or "tool class not found" in lowered:
        return {
            "error_type": "tool_unavailable",
            "error_tool": tool_name,
            "error_stage": stage,
            "technical_reason": "Gerekli arac bulunamadi veya yuklenmemis.",
            "error_hint": "Eksik araci kurun veya tarama arac listesinden cikarin.",
        }

    if "operating_mode_violation" in lowered:
        return {
            "error_type": "policy_blocked",
            "error_tool": tool_name,
            "error_stage": stage,
            "technical_reason": "Guvenli calisma modu, izin verilmeyen islemi engelledi.",
            "error_hint": "Read-only modda yalnizca izinli HTTP metodlarini kullanin.",
        }

    return {
        "error_type": "runtime_error",
        "error_tool": tool_name,
        "error_stage": stage,
        "technical_reason": "Tarama sirasinda beklenmeyen bir calisma hatasi olustu.",
        "error_hint": "Detay icin loglari inceleyip taramayi tekrar deneyin.",
    }


def _build_scan_failure_details(scan: Any) -> Dict[str, Optional[str]]:
    tool_name, tool_error = _select_primary_tool_error(scan)
    raw_error = str(tool_error or getattr(scan, "error_message", "") or "")
    details = _classify_failure_details(
        raw_error=raw_error,
        tool_name=tool_name,
        stage=getattr(scan, "current_phase", None),
    )
    return details


def _safe_parse_datetime(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _sanitize(obj: Any) -> Any:
    """Herhangi bir nesneyi JSON-safe plain dict/list'e dönüştür.
    Döngüsel referansları ve serialize edilemeyen tipleri str'e çevirir."""
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return {} if isinstance(obj, dict) else [] if isinstance(obj, list) else str(obj)


def _normalize_scan_status(value: Any) -> ScanStatus:
    normalized = str(value or "pending").lower()
    try:
        return ScanStatus(normalized)
    except Exception:
        return ScanStatus.PENDING


class ScanStatusResponse(BaseModel):
    """Scan durum yanıtı - Enhanced"""
    scan_id: str
    target_url: str
    status: ScanStatus
    progress: int = Field(0, ge=0, le=100, description="Tamamlanma yüzdesi")
    
    @validator("progress", pre=True)
    def clamp_progress(cls, v):
        if v is None: return 0
        try:
            val = int(v)
            return max(0, min(val, 100))
        except (ValueError, TypeError):
            return 0
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
    error_type: Optional[str] = None
    error_tool: Optional[str] = None
    error_stage: Optional[str] = None
    technical_reason: Optional[str] = None
    error_hint: Optional[str] = None
    
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
    owner_id = _get_owner_id(request)
    logger.info(f"[SCAN_REQUEST] target_url={target_url}, scan_type={scan_request.scan_type}, authorization={scan_request.authorization_acknowledged}, scope_len={len(scan_request.scope_statement)}")
    
    # DIAGNOSTIC: Log authorization details
    logger.debug(f"[AUTH_CHECK] authorization_acknowledged={repr(scan_request.authorization_acknowledged)}, type={type(scan_request.authorization_acknowledged).__name__}")

    # Araçları belirle
    tools = scan_request.tools
    if not tools:
        tools = filter_installed_tool_names(get_default_tool_names(scan_request.scan_type.value))
    else:
        tools = [canonical_tool_name(tool_name) for tool_name in tools]

    # Preserve order but remove duplicates to avoid repeated tool runs.
    deduped_tools = []
    seen_tools = set()
    for tool_name in tools:
        if tool_name in seen_tools:
            continue
        seen_tools.add(tool_name)
        deduped_tools.append(tool_name)
    if len(deduped_tools) != len(tools):
        logger.info(f"[SCAN_REQUEST] Deduplicated tools: {len(tools)} -> {len(deduped_tools)}")
    tools = deduped_tools
    
    # Authorization acknowledgement required
    if not scan_request.authorization_acknowledged:
        raise HTTPException(status_code=400, detail="Authorization acknowledgement is required to start an assessment")

    # Domain verification enforcement (skip for local targets)
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    if settings.DOMAIN_VERIFICATION_REQUIRED and not _is_local_target(hostname):
        if not scan_request.domain_verification_token:
            raise HTTPException(status_code=403, detail="Domain verification token is required for this target")

        token_record = get_verification_token(hostname, scan_request.domain_verification_token)
        if not token_record:
            raise HTTPException(status_code=403, detail="Invalid or missing domain verification token for this target")

        expires_at = _parse_dt(token_record.get("expires_at"))
        now = datetime.now(expires_at.tzinfo) if expires_at and expires_at.tzinfo else datetime.now()
        if expires_at and now > expires_at:
            raise HTTPException(status_code=403, detail="Domain verification token has expired")

        status = str(token_record.get("status") or "pending").lower()
        if status != "verified":
            raise HTTPException(status_code=403, detail="Domain verification token is not verified yet")

    if hostname:
        if settings.TARGET_DENYLIST and _host_in_list(hostname, settings.TARGET_DENYLIST):
            raise HTTPException(status_code=403, detail="Target is not allowed by denylist")
        if settings.TARGET_ALLOWLIST and not _host_in_list(hostname, settings.TARGET_ALLOWLIST):
            raise HTTPException(status_code=403, detail="Target is not in allowlist")

    # Tarama oluştur
    try:
        scan = scanner_engine.create_scan(
            target_url=target_url,
            scan_type=scan_request.scan_type.value,
            tools=tools,
            authorization_acknowledged=scan_request.authorization_acknowledged,
            scope_statement=scan_request.scope_statement,
            owner_id=owner_id,
        )
    except ValueError as ve:
        detail = str(ve)
        if "Only one active assessment per target is allowed at a time" in detail:
            raise HTTPException(status_code=409, detail=detail)
        raise HTTPException(status_code=400, detail=detail)
    
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
            
            # Normal scan - tool wrappers'ı çalıştır
            # Tool classes mapping (pure Python async + optional external)
            from app.tools.discovery.builtin_scanner_wrapper import (
                BasicInfoWrapper, SecurityHeadersWrapper, SSLScannerWrapper, PortScannerWrapper
            )
            from app.tools.discovery.crawler_async import AsyncCrawlerWrapper
            from app.tools.discovery.dir_bruteforce_async import DirBruteAsyncWrapper
            from app.tools.discovery.tech_fingerprint import TechFingerprintWrapper

            # New professional tools
            from app.tools.discovery.amass_wrapper import AmassWrapper
            from app.tools.discovery.nmap_wrapper import NmapWrapper
            from app.tools.discovery.nikto_wrapper import NiktoWrapper
            from app.tools.discovery.nuclei_wrapper import NucleiWrapper
            from app.tools.discovery.zap_scanner_wrapper import ZapScannerWrapper
            from app.tools.sast.semgrep_wrapper import SemgrepWrapper
            from app.tools.injection.wapiti_wrapper import WapitiWrapper
            from app.tools.injection.sqlmap_wrapper import SQLMapWrapper
            from app.tools.container.trivy_wrapper import TrivyWrapper
            from app.tools.secrets.gitleaks_wrapper import GitleaksWrapper

            tool_classes = {
                # Built-in async tools (no external binaries)
                "crawler": AsyncCrawlerWrapper,
                "dir_brute": DirBruteAsyncWrapper,
                "fingerprint": TechFingerprintWrapper,
                "basic": BasicInfoWrapper,
                "headers": SecurityHeadersWrapper,
                "ssl": SSLScannerWrapper,
                "ports": PortScannerWrapper,

                # Professional integration tools
                "amass": AmassWrapper,
                "nmap": NmapWrapper,
                "nuclei": NucleiWrapper,
                "nikto": NiktoWrapper,
                "owasp_zap": ZapScannerWrapper,
                "semgrep": SemgrepWrapper,
                "sqlmap": SQLMapWrapper,
                "wapiti": WapitiWrapper,
                "trivy": TrivyWrapper,
                "gitleaks": GitleaksWrapper,
            }

            # Sadece kullanılacak tool'ları filtrele
            available_tools = {}
            logger.info(f"[SCAN_TASK] Target tools from request: {scan.tools}")
            for tool_name in scan.tools:
                if tool_name in {"crawler", "dir_brute", "fingerprint", "basic", "headers", "ssl", "ports"} and tool_name in tool_classes:
                    available_tools[tool_name] = {
                        "tool_class": tool_classes[tool_name],
                        "target": scan.target_url,
                        "options": build_tool_options(tool_name, scan.scan_type),
                    }
                elif tool_name in tool_classes:
                    plan = get_tool_plan(tool_name, scan.scan_type, scan.target_url)
                    if plan:
                        available_tools[tool_name] = plan
                else:
                    logger.warning(f"[SCAN_TASK] Tool '{tool_name}' requested but no wrapper found in tool_classes mapping")

            if available_tools:
                logger.info(f"[SCAN_TASK] Starting engine with tools: {list(available_tools.keys())}")
                await scanner_engine.run_scan(scan.scan_id, available_tools)
            else:
                logger.warning(f"No available tools for scan {scan.scan_id}")
                scan.status = EngineScanStatus.FAILED
                scan.error_message = "No available tools to run"
                scan.completed_at = datetime.now()
                upsert_scan_state(scan)
                    
        except Exception as e:
            logger.error(f"Error running scan task: {e}", exc_info=True)
            # ✅ FAIL-SAFE: Background task exception scan'i FAILED yapmalı
            scan = scanner_engine.get_scan(scan_id)  # ✅ Use captured scan_id
            if scan:
                scan.status = EngineScanStatus.FAILED
                scan.error_message = f"Background task exception: {str(e)}"
                scan.completed_at = datetime.now()
                upsert_scan_state(scan)
        finally:
            # ✅ FINAL GARANTISI: Scan mutlaka finalize edilir
            scan = scanner_engine.get_scan(scan_id)  # ✅ Use captured scan_id
            if scan and not scan.completed_at:
                # Hala tamamlanmamışsa force complete
                if scan.status == EngineScanStatus.RUNNING:
                    scan.status = EngineScanStatus.FAILED
                    scan.error_message = "Scan finalized by background task cleanup"
                scan.completed_at = datetime.now()
                upsert_scan_state(scan)
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
    
    owner_id = _get_owner_id(request)
    scan = scanner_engine.get_scan(scan_id)
    if scan:
        _ensure_owner_access(owner_id, scan, scan_id)

    if not scan:
        record = get_scan_record(scan_id, owner_id=owner_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")

        findings_rows = get_findings_for_scan(scan_id)
        findings_response = [
            FindingResponseItem(
                id=row.get("id", ""),
                title=row.get("title", "Unknown"),
                description=row.get("description", ""),
                risk_level=row.get("risk_level", "info"),
                affected_url=row.get("affected_url", ""),
                tool_name=row.get("tool_name", "unknown"),
                recommendation=row.get("recommendation", ""),
                confidence_score=float(row.get("confidence_score") or 0.0),
                verification_status=row.get("verification_status", "unverified"),
                sources=_sanitize(row.get("sources") or []),
                evidence=_sanitize(row.get("evidence") or {}),
                detection_method=row.get("detection_method", "automated"),
                found_at=_safe_parse_datetime(row.get("found_at")),
                cwe_id=row.get("cwe_id"),
                cvss_score=row.get("cvss_score"),
            )
            for row in findings_rows
        ]

        correlated_risks = record.get("correlated_risks") or []
        correlated_response: List[CorrelatedRiskItem] = []
        for risk in correlated_risks:
            correlated_response.append(CorrelatedRiskItem(
                id=risk.get("id"),
                title=risk.get("title"),
                single_risk_summary=risk.get("single_risk_summary") or risk.get("title") or "",
                risk_level=risk.get("risk_level", "info"),
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

        status = _normalize_scan_status(record.get("status"))
        failure_details = {
            "error_type": record.get("error_type"),
            "error_tool": record.get("error_tool"),
            "error_stage": record.get("error_stage"),
            "technical_reason": record.get("technical_reason"),
            "error_hint": record.get("error_hint"),
        }
        if status == ScanStatus.FAILED and not failure_details.get("error_type"):
            failure_details = _classify_failure_details(
                raw_error=str(record.get("error_message") or ""),
                tool_name=record.get("current_tool"),
                stage=record.get("current_phase"),
            )

        response = ScanStatusResponse(
            scan_id=record.get("scan_id", scan_id),
            target_url=record.get("target_url", ""),
            status=status,
            progress=max(0, min(int(record.get("progress") or 0), 100)),
            current_phase=record.get("current_phase"),
            current_tool=record.get("current_tool"),
            findings_count=int(record.get("findings_count") or len(findings_response)),
            findings_validated=int(record.get("findings_verified") or 0),
            findings_needs_review=int(record.get("findings_needs_review") or 0),
            findings=findings_response,
            correlated_risks=correlated_response,
            report_summary=record.get("report_summary") or None,
            started_at=_safe_parse_datetime(record.get("started_at")),
            completed_at=_safe_parse_datetime(record.get("completed_at")),
            error_message=record.get("error_message"),
            error_type=failure_details.get("error_type"),
            error_tool=failure_details.get("error_tool"),
            error_stage=failure_details.get("error_stage"),
            technical_reason=failure_details.get("technical_reason"),
            error_hint=failure_details.get("error_hint"),
            waf_detected=bool(record.get("waf_detected", False)),
            waf_vendor=record.get("waf_vendor"),
            rate_limiting_detected=bool(record.get("rate_limit_detected", False)),
            bot_protection_detected=bool(record.get("bot_protection_detected", False)),
            authorization_acknowledged=bool(record.get("authorization_acknowledged", False)),
            scope_statement=record.get("scope_statement"),
        )
    else:
        findings = scan.findings
        correlated_risks = scan.correlated_risks or []
        current_status = str(getattr(scan.status, "value", scan.status)).lower()
        if findings and current_status == "completed":
            findings = cross_validator.cross_validate_findings(findings)
            findings = cross_validator.validate_by_payload_matching(findings)

            findings = result_validator.validate_findings(
                findings,
                waf_detected=scan.waf_detected if hasattr(scan, 'waf_detected') else False
            )

            correlated_risks, findings = correlation_engine.correlate(
                findings,
                target_url=scan.target_url,
            )
            scan.correlated_risks = correlated_risks
            scan.report_summary = build_professional_report(scan, correlated_risks, findings)
            scan.findings = findings

        findings_validated = len([f for f in findings if hasattr(f, 'verification_status') and f.verification_status.value == "verified"])
        findings_needs_review = len([f for f in findings if hasattr(f, 'verification_status') and f.verification_status.value == "needs_manual_verification"])
        failure_details = _build_scan_failure_details(scan) if current_status == "failed" else {
            "error_type": None,
            "error_tool": None,
            "error_stage": None,
            "technical_reason": None,
            "error_hint": None,
        }

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
                sources=_sanitize(finding.sources),
                evidence=_sanitize(getattr(finding, "evidence", {}) or {}),
                detection_method=getattr(finding, "detection_method", None),
                found_at=getattr(finding, "found_at", None),
                cwe_id=finding.cwe_id,
                cvss_score=finding.cvss_score,
                evidence_quality_score=getattr(finding, "evidence_quality_score", None),
                false_positive_likelihood=getattr(finding, "false_positive_likelihood", None),
                exploitability_score=getattr(finding, "exploitability_score", None),
                reproducibility_steps=_sanitize(getattr(finding, "reproducibility_steps", None) or []) or None,
                validation_type=getattr(finding, "validation_type", None),
                correlated_with=_sanitize(getattr(finding, "correlated_with", None) or []) or None,
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
                correlated_findings=_sanitize(risk.get("correlated_findings") or []),
                attack_chain=_sanitize(risk.get("attack_chain") or []),
                next_probe=risk.get("next_probe"),
                attacker_would_try=risk.get("attacker_would_try"),
                business_impact=risk.get("business_impact"),
                what_blocked_exploitation=risk.get("what_blocked_exploitation"),
                false_positive_likelihood=risk.get("false_positive_likelihood"),
                exploitability_score=risk.get("exploitability_score"),
                manual_checklist=_sanitize(risk.get("manual_checklist") or []) or None,
                context=_sanitize(risk.get("context") or {}),
            ))

        response = ScanStatusResponse(
            scan_id=scan.scan_id,
            target_url=scan.target_url,
            status=_normalize_scan_status(getattr(scan.status, "value", scan.status)),
            progress=max(0, min(scan.progress, 100)),
            current_phase=getattr(scan, 'current_phase', None),
            current_tool=scan.current_tool,
            findings_count=len(findings),
            findings_validated=findings_validated,
            findings_needs_review=findings_needs_review,
            findings=findings_response,
            correlated_risks=correlated_response,
            report_summary=scan.report_summary or None,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
            error_type=failure_details.get("error_type"),
            error_tool=failure_details.get("error_tool"),
            error_stage=failure_details.get("error_stage"),
            technical_reason=failure_details.get("technical_reason"),
            error_hint=failure_details.get("error_hint"),
            waf_detected=getattr(scan, 'waf_detected', False),
            waf_vendor=getattr(scan, 'waf_vendor', None),
            rate_limiting_detected=getattr(scan, 'rate_limit_detected', False),
            bot_protection_detected=getattr(scan, 'bot_protection_detected', False),
            authorization_acknowledged=getattr(scan, 'authorization_acknowledged', False),
            scope_statement=getattr(scan, 'scope_statement', None),
        )

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
    offset: int = Query(0, ge=0, description="Offset"),
    request: Request = None,
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
    
    owner_id = _get_owner_id(request) if request else None
    records = list_scan_records(status.value if status else None, limit, offset, owner_id=owner_id)
    responses: List[ScanStatusResponse] = []

    for record in records:
        responses.append(
            ScanStatusResponse(
                scan_id=record.get("scan_id", ""),
                target_url=record.get("target_url", ""),
                status=_normalize_scan_status(record.get("status")),
                progress=max(0, min(int(record.get("progress") or 0), 100)),
                current_phase=record.get("current_phase"),
                current_tool=record.get("current_tool"),
                findings_count=int(record.get("findings_count") or 0),
                findings_validated=int(record.get("findings_verified") or 0),
                findings_needs_review=int(record.get("findings_needs_review") or 0),
                correlated_risks=[],
                report_summary=record.get("report_summary") or None,
                started_at=_safe_parse_datetime(record.get("started_at")),
                completed_at=_safe_parse_datetime(record.get("completed_at")),
                error_message=record.get("error_message"),
                waf_detected=bool(record.get("waf_detected", False)),
                waf_vendor=record.get("waf_vendor"),
                rate_limiting_detected=bool(record.get("rate_limit_detected", False)),
                bot_protection_detected=bool(record.get("bot_protection_detected", False)),
                authorization_acknowledged=bool(record.get("authorization_acknowledged", False)),
                scope_statement=record.get("scope_statement"),
            )
        )

    if responses:
        return responses

    # Fallback for scans created before DB persistence or if persistence temporarily unavailable.
    for scan in scanner_engine.active_scans.values():
        if owner_id and getattr(scan, "owner_id", None) != owner_id:
            continue
        normalized = _normalize_scan_status(getattr(scan.status, "value", scan.status))
        if status and normalized != status:
            continue
        responses.append(
            ScanStatusResponse(
                scan_id=scan.scan_id,
                target_url=scan.target_url,
                status=normalized,
                progress=max(0, min(int(scan.progress or 0), 100)),
                current_phase=getattr(scan, "current_phase", None),
                current_tool=getattr(scan, "current_tool", None),
                findings_count=len(getattr(scan, "findings", []) or []),
                findings_validated=0,
                findings_needs_review=0,
                correlated_risks=[],
                report_summary=getattr(scan, "report_summary", None),
                started_at=getattr(scan, "started_at", None),
                completed_at=getattr(scan, "completed_at", None),
                error_message=getattr(scan, "error_message", None),
                waf_detected=bool(getattr(scan, "waf_detected", False)),
                waf_vendor=getattr(scan, "waf_vendor", None),
                rate_limiting_detected=bool(getattr(scan, "rate_limit_detected", False)),
                bot_protection_detected=bool(getattr(scan, "bot_protection_detected", False)),
                authorization_acknowledged=bool(getattr(scan, "authorization_acknowledged", False)),
                scope_statement=getattr(scan, "scope_statement", None),
            )
        )

    return responses[offset : offset + limit]


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(scan_id: str, request: Request):
    """
    Çalışan bir taramayı iptal et
    
    Args:
        scan_id: Scan ID
    """
    
    logger.info(f"Cancelling scan: {scan_id}")

    owner_id = _get_owner_id(request)

    in_memory_scan = scanner_engine.get_scan(scan_id)
    if in_memory_scan:
        _ensure_owner_access(owner_id, in_memory_scan, scan_id)

    cancelled_in_engine = scanner_engine.stop_scan(scan_id)
    cancelled_in_db = mark_scan_cancelled(scan_id, "Scan stopped by user", owner_id=owner_id)

    if not in_memory_scan and not cancelled_in_db:
        raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")

    if in_memory_scan and not cancelled_in_engine:
        current_status = _normalize_scan_status(getattr(in_memory_scan.status, "value", in_memory_scan.status))
        if current_status not in {ScanStatus.CANCELLED, ScanStatus.COMPLETED, ScanStatus.FAILED}:
            raise HTTPException(status_code=409, detail=f"Assessment cannot be cancelled in status: {current_status.value}")

    return Response(status_code=204)


@router.post("/{scan_id}/retry", response_model=ScanResponse)
async def retry_scan(scan_id: str, background_tasks: BackgroundTasks, request: Request):
    """
    Başarısız olan bir taramayı tekrar dene
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Yeni scan bilgisi
    """
    
    logger.info(f"Retrying scan: {scan_id}")

    owner_id = _get_owner_id(request)
    source_scan = scanner_engine.get_scan(scan_id)
    if source_scan:
        _ensure_owner_access(owner_id, source_scan, scan_id)
    source_record = get_scan_record(scan_id, owner_id=owner_id) if source_scan is None else None

    if source_scan is None and source_record is None:
        raise HTTPException(status_code=404, detail=f"Assessment not found: {scan_id}")

    if source_scan is not None:
        source_status = _normalize_scan_status(getattr(source_scan.status, "value", source_scan.status))
        target_url = source_scan.target_url
        raw_scan_type = source_scan.scan_type
        tools = list(source_scan.tools or [])
        authorization_acknowledged = bool(getattr(source_scan, "authorization_acknowledged", False))
        scope_statement = getattr(source_scan, "scope_statement", None)
    else:
        source_status = _normalize_scan_status(source_record.get("status"))
        target_url = source_record.get("target_url")
        raw_scan_type = source_record.get("scan_type", "quick")
        tools = list(source_record.get("tools") or [])
        authorization_acknowledged = bool(source_record.get("authorization_acknowledged", False))
        scope_statement = source_record.get("scope_statement")

    if source_status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
        raise HTTPException(status_code=409, detail="Only completed/failed/cancelled assessments can be retried")

    if not authorization_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Cannot retry assessment without prior authorization acknowledgement",
        )

    try:
        retry_scan_type = ScanType(str(raw_scan_type).lower())
    except Exception:
        retry_scan_type = ScanType.CUSTOM

    if not target_url:
        raise HTTPException(status_code=400, detail="Cannot retry assessment: target URL is missing")

    effective_scope = scope_statement if scope_statement and len(scope_statement) >= 10 else "Retry assessment scope inherited from prior authorized assessment"

    retry_request = ScanRequest(
        target_url=target_url,
        scan_type=retry_scan_type,
        tools=tools,
        authorization_acknowledged=True,
        scope_statement=effective_scope,
    )

    return await create_scan(
        scan_request=retry_request,
        background_tasks=background_tasks,
        request=request,
    )
