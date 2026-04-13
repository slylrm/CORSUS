"""
Recon Scanner API Endpoints
Integrated from the tarama project – subdomain enumeration, SSL/TLS analysis,
directory fuzzing, and technology fingerprinting.
"""

from __future__ import annotations

import asyncio
import io
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel, Field

from app.utils.logger import logger

# Scanner imports (copied from tarama project)
from app.tools.recon.orchestrator import ScanConfig, WebSecurityScanner
from app.tools.recon.utils import normalize_target, safe_filename
from app.core.scanner import scanner_engine

router = APIRouter()

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _create_job(target: str) -> str:
    job_id = uuid.uuid4().hex
    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "target": target,
            "status": "queued",
            "progress": 0,
            "message": "Kuyrukta",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "result": None,
            "errors": [],
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


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan(job_id: str, target: str) -> None:
    try:
        normalized = normalize_target(target)
        scanner = WebSecurityScanner(
            ScanConfig(
                target_url=normalized.base_url,
                target_host=normalized.hostname,
                directory_wordlist=str(DEFAULT_DIR_WORDLIST),
                subdomain_wordlist=str(DEFAULT_SUBDOMAIN_WORDLIST),
                max_concurrency=40,
                timeout=15.0,
                dns_timeout=6.0,
                dns_retries=2,
                retries=2,
                request_delay=0.03,
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
        _update_job(
            job_id,
            status="failed",
            progress=100,
            message="Tarama basarisiz",
            errors=[str(exc)],
        )


def _status_label(status: str) -> str:
    mapping = {
        "queued": "Kuyrukta",
        "running": "Calisiyor",
        "completed": "Tamamlandi",
        "failed": "Basarisiz",
    }
    return mapping.get(status, status)


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
async def start_recon_scan(payload: ReconScanRequest):
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

    job_id = _create_job(normalized.raw_input)
    worker = threading.Thread(target=_run_scan, args=(job_id, normalized.raw_input), daemon=True)
    worker.start()

    return ReconScanStartResponse(job_id=job_id, status="queued")


@router.get("/status/{job_id}")
async def recon_scan_status(job_id: str):
    """
    Get the status / progress of a running recon scan.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    job["status_label"] = _status_label(job.get("status", ""))
    return job


@router.get("/result/{job_id}")
async def recon_scan_result(job_id: str):
    """
    Get the final result of a completed recon scan.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")
    return job.get("result") or {"errors": job.get("errors", [])}


@router.get("/export/{job_id}")
async def export_recon_json(job_id: str, pentest_id: Optional[str] = None):
    """
    Download scan result as JSON file.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")

    payload = job.get("result") or {"errors": job.get("errors", [])}
    
    if pentest_id:
        try:
            pt_scan = scanner_engine.get_scan(pentest_id)
            if pt_scan and getattr(pt_scan, 'findings', None):
                payload["vulnerabilities"] = []
                for f in pt_scan.findings:
                    payload["vulnerabilities"].append({
                        "id": f.id,
                        "title": f.title,
                        "description": f.description,
                        "risk_level": getattr(f.risk_level, 'value', str(f.risk_level)),
                        "affected_url": f.affected_url,
                        "recommendation": f.recommendation
                    })
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
async def export_recon_pdf(job_id: str, pentest_id: Optional[str] = None):
    """
    Download scan result as PDF report.
    """
    job = _get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Tarama gorevi bulunamadi.")
    if job.get("status") not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail="Tarama hala calisiyor.")

    payload = job.get("result") or {"errors": job.get("errors", [])}
    
    if pentest_id:
        try:
            pt_scan = scanner_engine.get_scan(pentest_id)
            if pt_scan and getattr(pt_scan, 'findings', None):
                payload["vulnerabilities"] = []
                for f in pt_scan.findings:
                    payload["vulnerabilities"].append({
                        "id": f.id,
                        "title": f.title,
                        "description": f.description,
                        "risk_level": getattr(f.risk_level, 'value', str(f.risk_level)),
                        "affected_url": f.affected_url,
                        "recommendation": f.recommendation
                    })
        except Exception as e:
            logger.error(f"Error appending pentest findings: {e}")

    filename = f"rapor-{safe_filename(job.get('target', 'target'))}-{job_id[:8]}.pdf"

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as pdf_canvas

        pdf_data = _build_pdf_report(job, payload, A4, pdf_canvas)
    except ImportError:
        # Fallback: return JSON if reportlab not installed
        data = json.dumps(payload, indent=2).encode("utf-8")
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename.replace(".pdf", ".json")}"'},
        )

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
        "ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s", "ü": "u",
        "Ç": "C", "Ğ": "G", "İ": "I", "Ö": "O", "Ş": "S", "Ü": "U",
    }
    return "".join(replacements.get(ch, ch) for ch in str(text))


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
