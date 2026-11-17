"""
Recon Scanner API Endpoints
Integrated from the tarama project - subdomain enumeration, SSL/TLS analysis,
directory fuzzing, and technology fingerprinting.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import BaseModel, Field

from app.utils.logger import logger
from app.config import settings

# Scanner imports (copied from tarama project)
from app.tools.recon.orchestrator import ScanConfig, WebSecurityScanner
from app.tools.recon.utils import normalize_target, safe_filename
from app.core.scanner import scanner_engine

router = APIRouter()


def _get_owner_id(request: Request) -> Optional[str]:
    return getattr(request.state, "owner_id", None)


def _ensure_owner_job(job: Dict[str, Any], owner_id: Optional[str]) -> None:
    if owner_id and job.get("owner_id") != owner_id:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")


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


def _enforce_target_lists(hostname: str) -> None:
    if settings.TARGET_DENYLIST and _host_in_list(hostname, settings.TARGET_DENYLIST):
        raise HTTPException(status_code=403, detail="Target is not allowed by denylist")
    if settings.TARGET_ALLOWLIST and not _host_in_list(hostname, settings.TARGET_ALLOWLIST):
        raise HTTPException(status_code=403, detail="Target is not in allowlist")

# ---------------------------------------------------------------------------
# Wordlist resolution
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent  # project root
WORDLIST_DIR = BASE_DIR / "wordlists"
DEFAULT_DIR_WORDLIST = (
    WORDLIST_DIR / "common_large.txt"
    if (WORDLIST_DIR / "common_large.txt").exists()
    else (
        WORDLIST_DIR / "common_medium.txt"
        if (WORDLIST_DIR / "common_medium.txt").exists()
        else WORDLIST_DIR / "common.txt"
    )
)
DEFAULT_SUBDOMAIN_WORDLIST = (
    WORDLIST_DIR / "subdomains_large.txt"
    if (WORDLIST_DIR / "subdomains_large.txt").exists()
    else WORDLIST_DIR / "subdomains.txt"
)

# ---------------------------------------------------------------------------
# In-memory job store (thread-safe)
# ---------------------------------------------------------------------------

jobs: Dict[str, Dict[str, Any]] = {}
jobs_lock = threading.Lock()
RECON_WORKER_COUNT = 1
recon_worker_slots = threading.BoundedSemaphore(value=RECON_WORKER_COUNT)


def _recon_runtime_limits() -> Dict[str, Any]:
    """Return runtime limits tuned for OS socket/select stability."""
    # Windows selector loop can hit fd limits with very high socket fan-out.
    if os.name == "nt":
        return {
            "max_concurrency": 24,
            "timeout": 7.0,
            "dns_timeout": 6.0,
            "dns_retries": 2,
            "retries": 1,
            "request_delay": 0.01,
            "directory_max_paths": 2500,
            "directory_max_variants_per_seed": 4,
            "directory_early_stop_streak": 120,
            "directory_min_early_stop_samples": 180,
        }

    return {
        "max_concurrency": 50,
        "timeout": 7.0,
        "dns_timeout": 6.0,
        "dns_retries": 2,
        "retries": 1,
        "request_delay": 0.0,
        "directory_max_paths": 6000,
        "directory_max_variants_per_seed": 4,
        "directory_early_stop_streak": 220,
        "directory_min_early_stop_samples": 260,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _create_job(target: str, owner_id: Optional[str] = None) -> str:
    job_id = uuid.uuid4().hex
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "target": target,
            "owner_id": owner_id,
            "status": "queued",
            "progress": 0,
            "message": "Kuyrukta",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "result": None,
            "errors": [],
            "failure_details": None,
        }
    return job_id


def _update_job(job_id: str, **updates: Any) -> None:
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return
        job.update(updates)
        job["updated_at"] = _utc_now()


def _get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with jobs_lock:
        job = jobs.get(job_id)
        if job is None:
            return None
        return json.loads(json.dumps(job))


def _status_label(status: str) -> str:
    mapping = {
        "queued": "Kuyrukta",
        "running": "Calisiyor",
        "completed": "Tamamlandi",
        "failed": "Basarisiz",
    }
    return mapping.get(status, status)


def _infer_recon_stage(progress_message: str) -> Optional[str]:
    text = str(progress_message or "").lower()
    if "alt alan" in text:
        return "subdomains"
    if "tls" in text or "ssl" in text:
        return "ssl"
    if "dizin" in text:
        return "fuzz"
    if "teknoloji" in text:
        return "fingerprint"
    return None


def _stage_to_tool(stage: Optional[str]) -> Optional[str]:
    mapping = {
        "subdomains": "subdomain_enum",
        "ssl": "tls_analyzer",
        "fuzz": "dir_fuzz",
        "fingerprint": "tech_fingerprint",
    }
    return mapping.get(stage or "")


def _classify_recon_failure(raw_error: str, progress_message: str) -> Dict[str, Optional[str]]:
    lowered = str(raw_error or "").lower()
    stage = _infer_recon_stage(progress_message)
    tool_name = _stage_to_tool(stage)

    if "too many file descriptors" in lowered or ("select()" in lowered and "descriptor" in lowered):
        return {
            "error_type": "socket_limit",
            "tool_name": tool_name,
            "stage": stage,
            "technical_reason": "Sistemde acik socket/file descriptor limiti asildi.",
            "hint": "Eszamanlilik dusurulmeli ve is yukleri daha kucuk partilerde calistirilmali.",
        }

    if "timeout" in lowered or "timed out" in lowered:
        return {
            "error_type": "timeout",
            "tool_name": tool_name,
            "stage": stage,
            "technical_reason": "Ag istegi veya recon asamasi zaman asimina ugradi.",
            "hint": "Hedef ulasilabilirligini kontrol edin ve timeout degerlerini artirin.",
        }

    if "dns" in lowered and ("resolve" in lowered or "failed" in lowered):
        return {
            "error_type": "dns_error",
            "tool_name": tool_name,
            "stage": stage,
            "technical_reason": "DNS cozumleme hatasi olustu.",
            "hint": "DNS erisimi ve hedef alan adinin gecerliligini kontrol edin.",
        }

    return {
        "error_type": "runtime_error",
        "tool_name": tool_name,
        "stage": stage,
        "technical_reason": "Recon calismasi sirasinda beklenmeyen bir hata olustu.",
        "hint": "Detayli hata metnini loglardan inceleyip tekrar deneyin.",
    }


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan(job_id: str, target: str) -> None:
    try:
        _update_job(job_id, status="queued", progress=0, message="Tarama sirasi bekleniyor")
        with recon_worker_slots:
            normalized = normalize_target(target)
            limits = _recon_runtime_limits()
            scanner = WebSecurityScanner(
                ScanConfig(
                    target_url=normalized.base_url,
                    target_host=normalized.hostname,
                    directory_wordlist=str(DEFAULT_DIR_WORDLIST),
                    subdomain_wordlist=str(DEFAULT_SUBDOMAIN_WORDLIST),
                    max_concurrency=limits["max_concurrency"],
                    timeout=limits["timeout"],
                    dns_timeout=limits["dns_timeout"],
                    dns_retries=limits["dns_retries"],
                    retries=limits["retries"],
                    request_delay=limits["request_delay"],
                    directory_max_paths=limits["directory_max_paths"],
                    directory_max_variants_per_seed=limits["directory_max_variants_per_seed"],
                    directory_early_stop_streak=limits["directory_early_stop_streak"],
                    directory_min_early_stop_samples=limits["directory_min_early_stop_samples"],
                )
            )

            def progress_callback(progress: int, message: str) -> None:
                _update_job(job_id, progress=progress, message=message, status="running")

            _update_job(job_id, status="running", progress=1, message="Tarama baslatiliyor")
            logger.info("Starting recon scan job {} for {}", job_id, target)
            scan_result = asyncio.run(scanner.run(progress_callback))
            _update_job(
                job_id,
                status="completed",
                progress=100,
                message="Tarama tamamlandi",
                result=scan_result,
            )
            logger.info("Completed recon scan job {} for {}", job_id, target)
    except Exception as exc:
        logger.exception("Recon scan job {} failed", job_id)
        current = _get_job(job_id) or {}
        try:
            previous_progress = int(current.get("progress", 0))
        except (TypeError, ValueError):
            previous_progress = 0

        raw_error = str(exc)
        failure_details = _classify_recon_failure(raw_error, str(current.get("message", "")))
        failed_message = f"Tarama basarisiz: {failure_details.get('technical_reason')}"
        tool_name = failure_details.get("tool_name")
        if tool_name:
            failed_message = f"{failed_message} (arac: {tool_name})"

        failed_progress = max(0, min(previous_progress, 95))
        _update_job(
            job_id,
            status="failed",
            progress=failed_progress,
            message=failed_message,
            errors=[raw_error],
            failure_details=failure_details,
        )


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ReconScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or domain (e.g. https://example.com)")


class ReconScanStartResponse(BaseModel):
    job_id: str
    status: str


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.post("/start", response_model=ReconScanStartResponse)
async def start_recon_scan(payload: ReconScanRequest, request: Request):
    """
    Start a recon scan (subdomain enum, SSL analysis, dir fuzzing, tech fingerprinting).
    """
    target = payload.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Hedef URL zorunludur.")

    try:
        normalized = normalize_target(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _enforce_target_lists(normalized.hostname)
    owner_id = _get_owner_id(request)
    job_id = _create_job(normalized.raw_input, owner_id=owner_id)
    worker = threading.Thread(target=_run_scan, args=(job_id, normalized.raw_input), daemon=True)
    worker.start()

    return ReconScanStartResponse(job_id=job_id, status="queued")


@router.get("/status/{job_id}")
async def recon_scan_status(job_id: str, request: Request):
    """
    Get the status / progress of a running recon scan.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    _ensure_owner_job(job, _get_owner_id(request))
    if job.get("status") == "failed" and not job.get("failure_details"):
        raw_error = "; ".join([str(item) for item in (job.get("errors") or [])])
        job["failure_details"] = _classify_recon_failure(raw_error, str(job.get("message", "")))
    job["status_label"] = _status_label(job.get("status", ""))
    return job


@router.get("/result/{job_id}")
async def recon_scan_result(job_id: str, request: Request):
    """
    Get the final result of a completed recon scan.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    _ensure_owner_job(job, _get_owner_id(request))
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")
    return job.get("result") or {"errors": job.get("errors", [])}


@router.get("/export/{job_id}")
async def export_recon_json(job_id: str, pentest_id: Optional[str] = None, request: Request = None):
    """
    Download scan result as JSON file.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    if request:
        _ensure_owner_job(job, _get_owner_id(request))
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")

    payload = job.get("result") or {"errors": job.get("errors", [])}

    if pentest_id:
        try:
            pt_scan = scanner_engine.get_scan(pentest_id)
            if pt_scan and getattr(pt_scan, "findings", None):
                payload["vulnerabilities"] = []
                for f in pt_scan.findings:
                    payload["vulnerabilities"].append(
                        {
                            "id": f.id,
                            "title": f.title,
                            "description": f.description,
                            "risk_level": getattr(f.risk_level, "value", str(f.risk_level)),
                            "affected_url": f.affected_url,
                            "recommendation": f.recommendation,
                        }
                    )
        except Exception as e:
            logger.error(f"Error appending pentest findings: {e}")

    filename = f"scan-{safe_filename(job.get('target', 'target'))}-{job_id[:8]}.json"
    data = json.dumps(payload, indent=2).encode("utf-8")
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/pdf/{job_id}")
async def export_recon_pdf(job_id: str, pentest_id: Optional[str] = None, request: Request = None):
    """
    Download scan result as PDF report.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    if request:
        _ensure_owner_job(job, _get_owner_id(request))
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")

    payload = job.get("result") or {"errors": job.get("errors", [])}

    if pentest_id:
        try:
            pt_scan = scanner_engine.get_scan(pentest_id)
            if pt_scan and getattr(pt_scan, "findings", None):
                payload["vulnerabilities"] = []
                for f in pt_scan.findings:
                    payload["vulnerabilities"].append(
                        {
                            "id": f.id,
                            "title": f.title,
                            "description": f.description,
                            "risk_level": getattr(f.risk_level, "value", str(f.risk_level)),
                            "affected_url": f.affected_url,
                            "recommendation": f.recommendation,
                        }
                    )
        except Exception as e:
            logger.error(f"Error appending pentest findings: {e}")

    filename = f"rapor-{safe_filename(job.get('target', 'target'))}-{job_id[:8]}.pdf"

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as pdf_canvas

        pdf_data = _build_pdf_report(job, payload, A4, pdf_canvas)
    except ImportError:
        logger.warning("reportlab is not installed; using built-in PDF fallback for recon export")
        pdf_data = _build_plain_pdf_fallback(job, payload)

    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# PDF helper
# ---------------------------------------------------------------------------

def _pdf_line(text: str) -> str:
    replacements = {
        "\u00e7": "c", "\u011f": "g", "\u0131": "i", "\u00f6": "o", "\u015f": "s", "\u00fc": "u",
        "\u00c7": "C", "\u011e": "G", "\u0130": "I", "\u00d6": "O", "\u015e": "S", "\u00dc": "U",
    }
    return "".join(replacements.get(ch, ch) for ch in str(text))


def _simple_pdf_bytes(lines: List[str]) -> bytes:
    """Generate a tiny dependency-free PDF document."""

    def esc(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_lines = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
    for idx, line in enumerate(lines[:260]):
        safe = esc((line or "")[:120])
        if idx == 0:
            content_lines.append(f"({safe}) Tj")
        else:
            content_lines.append("T*")
            content_lines.append(f"({safe}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    )
    objects.append(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objects.append(
        b"5 0 obj\n<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream\nendobj\n"
    )

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
    )
    return bytes(pdf)


def _build_plain_pdf_fallback(job: Dict[str, Any], payload: Dict[str, Any]) -> bytes:
    """Fallback export content used when reportlab is unavailable."""

    target = payload.get("target", {})
    subdomains = payload.get("subdomains", {})
    ssl_info = payload.get("ssl", {})
    directories = payload.get("directories", {})
    technologies = payload.get("technologies", {})
    vulnerabilities = payload.get("vulnerabilities", [])

    lines: List[str] = [
        "Recon Scan Report",
        f"Target: {target.get('normalized_url', job.get('target', '-'))}",
        f"Date: {payload.get('scan_timestamp', '-')}",
        f"Status: {_status_label(job.get('status', '-'))}",
        "",
        f"Live subdomains: {len(subdomains.get('live_subdomains', []))}",
        f"SSL reachable: {ssl_info.get('reachable')}",
        f"Directory findings: {len(directories.get('findings', []))}",
        f"Technology detections: {len(technologies.get('technologies', []))}",
        f"Vulnerabilities: {len(vulnerabilities)}",
        "",
        "Vulnerabilities:",
    ]

    for idx, finding in enumerate(vulnerabilities[:120], start=1):
        risk = str(finding.get("risk_level", "unknown")).upper()
        title = str(finding.get("title", "Untitled"))
        lines.append(f"{idx}. [{risk}] {title}")
        if finding.get("affected_url"):
            lines.append(f"   URL: {finding.get('affected_url')}")
        if finding.get("recommendation"):
            lines.append(f"   Recommendation: {finding.get('recommendation')}")

    errors = payload.get("errors", []) or job.get("errors", [])
    if errors:
        lines.append("")
        lines.append("Errors:")
        for err in errors[:40]:
            lines.append(f"- {err}")

    return _simple_pdf_bytes(lines)


def _build_pdf_report(job, payload, A4, pdf_canvas) -> bytes:
    buffer = io.BytesIO()
    pdf = pdf_canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    left = 40
    y = height - 45

    def draw_title(text):
        nonlocal y
        if y < 90:
            pdf.showPage()
            y = height - 45
        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(left, y, _pdf_line(text))
        y -= 18

    def draw_line(text, indent=0):
        nonlocal y
        if y < 45:
            pdf.showPage()
            y = height - 45
        pdf.setFont("Helvetica", 10)
        safe = _pdf_line(text)
        max_len = 118 - indent // 2
        for i in range(0, len(safe), max_len):
            pdf.drawString(left + indent, y, safe[i:i + max_len])
            y -= 13

    target = payload.get("target", {})
    subdomains = payload.get("subdomains", {})
    ssl_info = payload.get("ssl", {})
    directories = payload.get("directories", {})
    tech = payload.get("technologies", {})

    draw_title("Tarama Raporu")
    draw_line(f"Hedef: {target.get('normalized_url', job.get('target', '-'))}")
    draw_line(f"Tarih: {payload.get('scan_timestamp', '-')}")
    draw_line(f"Durum: {_status_label(job.get('status', '-'))}")
    y -= 6

    draw_title("1) Alt Alan Adlari")
    live_subs = subdomains.get("live_subdomains", [])
    draw_line(f"Canli alt alan adi sayisi: {len(live_subs)}")
    for item in live_subs[:200]:
        draw_line(f"- {item}", indent=12)

    y -= 6
    draw_title("2) SSL/TLS")
    draw_line(f"Erisilebilir: {ssl_info.get('reachable')}")
    draw_line(f"Protokol: {ssl_info.get('protocol')}")
    certificate = ssl_info.get("certificate", {})
    draw_line(f"Sertifika Veren: {certificate.get('issuer')}")
    draw_line(f"Gecerlilik Sonu: {certificate.get('not_after')}")
    for issue in ssl_info.get("issues", []):
        draw_line(f"- Risk: {issue}", indent=12)

    y -= 6
    draw_title("3) Dizin ve Uc Nokta Taramasi")
    findings = directories.get("findings", [])
    draw_line(f"Test edilen yol sayisi: {directories.get('paths_tested', 0)}")
    draw_line(f"Bulunan kayit sayisi: {len(findings)}")
    for item in findings[:200]:
        draw_line(f"- {item.get('status')} {item.get('path')}", indent=12)

    y -= 6
    draw_title("4) Teknoloji Parmak Izi")
    technologies = tech.get("technologies", [])
    draw_line(f"Tespit sayisi: {len(technologies)}")
    for entry in technologies:
        draw_line(f"- {entry.get('name')} ({entry.get('category')})", indent=12)

    vulnerabilities = payload.get("vulnerabilities", [])
    if vulnerabilities:
        y -= 6
        draw_title("5) Vulnerabilities")
        draw_line(f"Deep penetrative discoveries: {len(vulnerabilities)}")
        for i, vul in enumerate(vulnerabilities[:50]):
            draw_line(f"- [{str(vul['risk_level']).upper()}] {vul['title']}", indent=12)
            if vul.get("affected_url"):
                draw_line(f"  Url: {vul['affected_url']}", indent=14)

    errors = payload.get("errors", []) or job.get("errors", [])
    if errors:
        y -= 6
        draw_title("Hatalar")
        for err in errors:
            draw_line(f"- {err}", indent=12)

    pdf.save()
    buffer.seek(0)
    return buffer.getvalue()
