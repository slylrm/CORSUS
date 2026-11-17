"""
Reports API Endpoints
Tarama sonuç raporları
"""

from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum
import json
from typing import Any

from app.utils.logger import logger
from app.core.scanner import scanner_engine
from app.core.persistence import get_findings_for_scan, get_scan_record


def _sanitize(obj: Any) -> Any:
    """Round-trip through JSON to strip non-serialisable / circular objects."""
    try:
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return {} if isinstance(obj, dict) else [] if isinstance(obj, list) else str(obj)


router = APIRouter()


def _get_owner_id(request: Request) -> Optional[str]:
    return getattr(request.state, "owner_id", None)


def _ensure_owner_access(owner_id: Optional[str], scan_or_record: Any, scan_id: str) -> None:
    if not owner_id:
        return
    if isinstance(scan_or_record, dict):
        if scan_or_record.get("owner_id") != owner_id:
            raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")
    else:
        if getattr(scan_or_record, "owner_id", None) != owner_id:
            raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")


def _is_verified(finding) -> bool:
    verification_status = getattr(finding, "verification_status", None)
    if verification_status is not None:
        value = getattr(verification_status, "value", verification_status)
        return value == "verified"
    return bool(getattr(finding, "verified", False))


def _parse_dt(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _risk_value(finding) -> str:
    risk_level = getattr(finding, "risk_level", None)
    if risk_level is None and isinstance(finding, dict):
        risk_level = finding.get("risk_level")
    return str(getattr(risk_level, "value", risk_level or "info")).lower()


def _simple_pdf_bytes(lines: List[str]) -> bytes:
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


class ReportFormat(str, Enum):
    """Rapor formatları"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "md"


class FindingSummary(BaseModel):
    """Bulgu özeti"""
    risk_level: str
    count: int
    percentage: float


class ReportSummary(BaseModel):
    """Rapor özeti"""
    scan_id: str
    target_url: str
    scan_date: datetime
    scan_duration_seconds: int
    total_findings: int
    findings_by_risk: List[FindingSummary]
    tools_used: List[str]
    verified_findings: int
    false_positives: int


class FindingDetail(BaseModel):
    """Detaylı bulgu"""
    id: str
    title: str
    description: str
    risk_level: str
    affected_url: str
    evidence: dict
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    verified: bool
    tool_name: str
    found_at: datetime


class DetailedReport(BaseModel):
    """Detaylı rapor"""
    summary: ReportSummary
    findings: List[FindingDetail]
    executive_summary: str
    recommendations: List[str]


def _finding_to_lines(finding: FindingDetail) -> List[str]:
    evidence = finding.evidence or {}
    lines = [
        f"   Description: {finding.description}",
        f"   URL: {finding.affected_url}",
        f"   Tool: {finding.tool_name}",
        f"   Verified: {finding.verified}",
    ]
    if finding.cwe_id:
        lines.append(f"   CWE: {finding.cwe_id}")
    if finding.cvss_score is not None:
        lines.append(f"   CVSS: {finding.cvss_score}")
    if finding.found_at:
        lines.append(f"   Found at: {finding.found_at.isoformat()}")
    if finding.recommendation:
        lines.append(f"   Recommendation: {finding.recommendation}")
    if evidence:
        lines.append("   Evidence:")
        for key in ["raw", "endpoint", "issue_type", "references", "potential_false_positive", "endpoints", "template", "matcher-name", "extracted-results", "curl-command"]:
            if key in evidence and evidence.get(key) not in (None, "", [], {}):
                lines.append(f"     - {key}: {evidence.get(key)}")
    return lines


@router.get("/{scan_id}/summary", response_model=ReportSummary)
async def get_report_summary(scan_id: str, request: Request):
    """
    Tarama sonuç özeti
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Yönetici özeti (executive summary)
    """
    
    owner_id = _get_owner_id(request)
    scan = scanner_engine.get_scan(scan_id)
    if scan:
        _ensure_owner_access(owner_id, scan, scan_id)

    if scan:
        findings = list(scan.findings or [])
        target_url = scan.target_url
        scan_date = scan.created_at
        tools_used = list(scan.tools or [])
        started_at = scan.started_at
        completed_at = scan.completed_at
        verified_findings = sum(1 for f in findings if _is_verified(f))
        false_positives = sum(
            1
            for f in findings
            if str(getattr(getattr(f, "verification_status", None), "value", "")).lower() == "false_positive"
        )
    else:
        record = get_scan_record(scan_id, owner_id=owner_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")

        findings = get_findings_for_scan(scan_id)
        target_url = record.get("target_url", "")
        scan_date = _parse_dt(record.get("created_at")) or datetime.now()
        tools_used = list(record.get("tools") or [])
        started_at = _parse_dt(record.get("started_at"))
        completed_at = _parse_dt(record.get("completed_at"))
        verified_findings = sum(1 for f in findings if str(f.get("verification_status", "")).lower() == "verified")
        false_positives = sum(1 for f in findings if str(f.get("verification_status", "")).lower() == "false_positive")

    findings_by_risk = {}
    for finding in findings:
        risk = _risk_value(finding)
        findings_by_risk[risk] = findings_by_risk.get(risk, 0) + 1

    total = len(findings)
    risk_summary = []
    for risk in ["critical", "high", "medium", "low", "info"]:
        count = findings_by_risk.get(risk, 0)
        percentage = (count / total * 100) if total > 0 else 0
        risk_summary.append(FindingSummary(
            risk_level=risk,
            count=count,
            percentage=round(percentage, 1)
        ))

    duration = 0
    if started_at and completed_at:
        duration = int((completed_at - started_at).total_seconds())

    return ReportSummary(
        scan_id=scan_id,
        target_url=target_url,
        scan_date=scan_date,
        scan_duration_seconds=max(duration, 0),
        total_findings=total,
        findings_by_risk=risk_summary,
        tools_used=tools_used,
        verified_findings=verified_findings,
        false_positives=false_positives,
    )


@router.get("/{scan_id}/detailed", response_model=DetailedReport)
async def get_detailed_report(scan_id: str, request: Request):
    """
    Detaylı tarama raporu
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Tüm bulgular ve detaylar
    """
    
    owner_id = _get_owner_id(request)
    scan = scanner_engine.get_scan(scan_id)
    if scan:
        _ensure_owner_access(owner_id, scan, scan_id)
    record = get_scan_record(scan_id, owner_id=owner_id) if scan is None else None

    if scan is None and record is None:
        raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")

    summary = await get_report_summary(scan_id, request)

    if scan:
        findings = [
            FindingDetail(
                id=f.id,
                title=f.title,
                description=f.description,
                risk_level=f.risk_level.value,
                affected_url=f.affected_url,
                evidence=_sanitize(f.evidence),
                recommendation=f.recommendation,
                cwe_id=f.cwe_id,
                cvss_score=f.cvss_score,
                verified=_is_verified(f),
                tool_name=f.tool_name,
                found_at=f.found_at
            )
            for f in scan.findings
        ]
    else:
        findings_rows = get_findings_for_scan(scan_id)
        findings = [
            FindingDetail(
                id=row.get("id", ""),
                title=row.get("title", "Unknown"),
                description=row.get("description", ""),
                risk_level=row.get("risk_level", "info"),
                affected_url=row.get("affected_url", ""),
                evidence=_sanitize(row.get("evidence") or {}),
                recommendation=row.get("recommendation", ""),
                cwe_id=row.get("cwe_id"),
                cvss_score=row.get("cvss_score"),
                verified=str(row.get("verification_status", "")).lower() == "verified",
                tool_name=row.get("tool_name", "unknown"),
                found_at=_parse_dt(row.get("found_at")) or datetime.now(),
            )
            for row in findings_rows
        ]

    critical_count = sum(1 for f in findings if f.risk_level == "critical")
    high_count = sum(1 for f in findings if f.risk_level == "high")
    
    target_url = summary.target_url
    if critical_count > 0:
        exec_summary = f"⚠️ KRİTİK: {target_url} için yapılan güvenlik taramasında {critical_count} kritik ve {high_count} yüksek riskli güvenlik açığı tespit edildi. Acil müdahale gereklidir."
    elif high_count > 0:
        exec_summary = f"⚠️ YÜKSEK RİSK: {target_url} için yapılan güvenlik taramasında {high_count} yüksek riskli güvenlik açığı tespit edildi. Öncelikli olarak ele alınmalıdır."
    else:
        exec_summary = f"✅ {target_url} için yapılan güvenlik taramasında kritik veya yüksek riskli güvenlik açığı tespit edilmedi. Düşük ve orta seviye bulgular gözden geçirilmelidir."
    
    # Genel öneriler
    recommendations = [
        "HTTPS protokolü kullanın ve tüm HTTP trafiğini HTTPS'e yönlendirin",
        "Güvenlik başlıklarını (Security Headers) ekleyin",
        "Düzenli güvenlik güncellemeleri yapın",
        "Güçlü şifreleme algoritmaları kullanın",
        "Gereksiz portları ve servisleri kapatın"
    ]
    
    return DetailedReport(
        summary=summary,
        findings=findings,
        executive_summary=exec_summary,
        recommendations=recommendations
    )


@router.get("/{scan_id}/export")
async def export_report(
    scan_id: str,
    format: ReportFormat = ReportFormat.JSON,
    request: Request = None,
):
    """
    Raporu belirtilen formatta indir
    
    Args:
        scan_id: Scan ID
        format: Rapor formatı (json, html, pdf, md)
        
    Returns:
        Rapor dosyası
    """
    
    logger.info(f"Exporting report {scan_id} as {format}")
    
    # Detaylı raporu al
    detailed_report = await get_detailed_report(scan_id, request)
    
    if format == ReportFormat.JSON:
        payload = detailed_report.model_dump(mode="json")
        payload["generated_at"] = datetime.now().isoformat()
        payload["format"] = "json"
        content = json.dumps(payload, indent=2, default=str)
        media_type = "application/json"
        filename = f"report_{scan_id}.json"
        
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    elif format == ReportFormat.HTML:
        # TODO: Jinja2 template ile HTML generate et
        html_content = _generate_html_report(detailed_report)
        
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f"attachment; filename=report_{scan_id}.html"
            }
        )
    
    elif format == ReportFormat.PDF:
        pdf_lines = [
            f"WeppenTest Security Report - {detailed_report.summary.scan_id}",
            f"Target: {detailed_report.summary.target_url}",
            f"Scan Date: {detailed_report.summary.scan_date.isoformat()}",
            f"Scan Duration (s): {detailed_report.summary.scan_duration_seconds}",
            f"Total Findings: {detailed_report.summary.total_findings}",
            f"Verified Findings: {detailed_report.summary.verified_findings}",
            f"False Positives: {detailed_report.summary.false_positives}",
            f"Tools Used: {', '.join(detailed_report.summary.tools_used) if detailed_report.summary.tools_used else '-'}",
            "",
            "Executive Summary:",
            detailed_report.executive_summary.strip(),
            "",
            "Risk Distribution:",
        ]
        for risk in detailed_report.summary.findings_by_risk:
            pdf_lines.append(f"- {risk.risk_level.upper()}: {risk.count} ({risk.percentage:.1f}%)")
        pdf_lines.extend([
            "Findings:",
        ])
        for idx, finding in enumerate(detailed_report.findings, start=1):
            pdf_lines.append(f"{idx}. [{finding.risk_level.upper()}] {finding.title} ({finding.tool_name})")
            pdf_lines.extend(_finding_to_lines(finding))
            pdf_lines.append("")

        if detailed_report.recommendations:
            pdf_lines.append("Recommendations:")
            for idx, recommendation in enumerate(detailed_report.recommendations, start=1):
                pdf_lines.append(f"{idx}. {recommendation}")

        pdf_content = _simple_pdf_bytes(pdf_lines)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"
            }
        )
    
    elif format == ReportFormat.MARKDOWN:
        md_content = _generate_markdown_report(detailed_report)
        
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f"attachment; filename=report_{scan_id}.md"
            }
        )


@router.get("/{scan_id}/findings/{risk_level}")
async def get_findings_by_risk(
    scan_id: str,
    risk_level: str,
    request: Request,
):
    """
    Belirli risk seviyesindeki bulguları getir
    
    Args:
        scan_id: Scan ID
        risk_level: Risk seviyesi (critical, high, medium, low, info)
        
    Returns:
        Filtrelenmiş bulgular
    """
    
    allowed_levels = {"critical", "high", "medium", "low", "info"}
    normalized_level = risk_level.lower().strip()
    if normalized_level not in allowed_levels:
        raise HTTPException(status_code=400, detail=f"Invalid risk level: {risk_level}")

    owner_id = _get_owner_id(request)
    scan = scanner_engine.get_scan(scan_id)
    if scan:
        _ensure_owner_access(owner_id, scan, scan_id)
    findings_payload = []

    if scan:
        for finding in scan.findings:
            if _risk_value(finding) != normalized_level:
                continue
            findings_payload.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "risk_level": finding.risk_level.value,
                    "affected_url": finding.affected_url,
                    "tool_name": finding.tool_name,
                    "recommendation": finding.recommendation,
                    "verified": _is_verified(finding),
                    "found_at": finding.found_at,
                }
            )
    else:
        record = get_scan_record(scan_id, owner_id=owner_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")
        rows = get_findings_for_scan(scan_id, normalized_level)
        findings_payload = [
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "description": row.get("description"),
                "risk_level": row.get("risk_level"),
                "affected_url": row.get("affected_url"),
                "tool_name": row.get("tool_name"),
                "recommendation": row.get("recommendation"),
                "verified": str(row.get("verification_status", "")).lower() == "verified",
                "found_at": _parse_dt(row.get("found_at")),
            }
            for row in rows
        ]

    return {
        "scan_id": scan_id,
        "risk_level": normalized_level,
        "count": len(findings_payload),
        "findings": findings_payload,
    }


def _generate_executive_summary(summary: ReportSummary) -> str:
    """Yönetici özeti oluştur"""
    
    critical_count = next((f.count for f in summary.findings_by_risk if f.risk_level == "critical"), 0)
    high_count = next((f.count for f in summary.findings_by_risk if f.risk_level == "high"), 0)
    
    return f"""
# 📊 Yönetici Özeti

**Taranan Site:** {summary.target_url}
**Tarama Tarihi:** {summary.scan_date.strftime('%Y-%m-%d %H:%M')}
**Toplam Bulgu:** {summary.total_findings}

## 🎯 Genel Değerlendirme

Bu rapor, {summary.target_url} web sitesinin güvenlik taraması sonuçlarını içermektedir.
Tarama sırasında {len(summary.tools_used)} farklı araç kullanılmıştır.

**Kritik Durumda Olan Bulgular:** {critical_count}
**Yüksek Riskli Bulgular:** {high_count}
**Doğrulanmış Bulgular:** {summary.verified_findings}

## ⚠️ Öncelikli Aksiyonlar

{'🔴 DERHAL: Kritik güvenlik açıkları tespit edildi. Acilen müdahale gerekiyor!' if critical_count > 0 else ''}
{'🟡 DİKKAT: Yüksek riskli bulgular mevcut. En kısa sürede giderilmeli.' if high_count > 0 and critical_count == 0 else ''}
{'🟢 Kritik bulgu tespit edilmedi. Ancak düşük-orta riskli bulgular gözden geçirilmelidir.' if critical_count == 0 and high_count == 0 else ''}

## 📈 Risk Dağılımı

{chr(10).join([f"- **{f.risk_level.upper()}:** {f.count} bulgu (%{f.percentage:.1f})" for f in summary.findings_by_risk])}
"""


def _generate_recommendations(findings: List[FindingDetail]) -> List[str]:
    """Genel öneriler oluştur"""
    
    recommendations = [
        "🔒 Tüm kritik ve yüksek riskli bulguları öncelikli olarak giderin",
        "🔍 Güvenlik taramalarını düzenli olarak (en az ayda bir) tekrarlayın",
        "📚 Geliştirme ekibine güvenli kodlama eğitimleri verin",
        "🛡️ Web Application Firewall (WAF) kullanımını değerlendirin",
        "🔐 HTTPS kullanımını zorunlu hale getirin",
        "📝 Güvenlik açıklarını giderme sürecinizi dokümante edin",
    ]
    
    return recommendations


def _generate_html_report(report: DetailedReport) -> str:
    """HTML rapor oluştur"""
    
    # Basit HTML template
    html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WeppenTest Güvenlik Raporu - {report.summary.scan_id}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 5px solid #ccc;
        }}
        .critical {{ border-left-color: #e53e3e; }}
        .high {{ border-left-color: #dd6b20; }}
        .medium {{ border-left-color: #d69e2e; }}
        .low {{ border-left-color: #38a169; }}
        .info {{ border-left-color: #3182ce; }}
        
        .risk-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .risk-critical {{ background: #feb2b2; color: #742a2a; }}
        .risk-high {{ background: #fbd38d; color: #7c2d12; }}
        .risk-medium {{ background: #faf089; color: #744210; }}
        .risk-low {{ background: #9ae6b4; color: #22543d; }}
        .risk-info {{ background: #90cdf4; color: #2c5282; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WeppenTest Güvenlik Raporu</h1>
        <p><strong>Taranan Site:</strong> {report.summary.target_url}</p>
        <p><strong>Tarama Tarihi:</strong> {report.summary.scan_date.strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Özet</h2>
        <p><strong>Toplam Bulgu:</strong> {report.summary.total_findings}</p>
        <p><strong>Doğrulanmış:</strong> {report.summary.verified_findings}</p>
        <p><strong>Tarama Süresi:</strong> {report.summary.scan_duration_seconds}s</p>
        
        <h3>Risk Dağılımı</h3>
        {''.join([f'<span class="risk-badge risk-{f.risk_level}">{f.risk_level.upper()}: {f.count}</span> ' for f in report.summary.findings_by_risk])}
    </div>
    
    <div class="summary">
        <h2>🔍 Bulgular</h2>
        {''.join([f'''
        <div class="finding {f.risk_level}">
            <h3>{f.title} <span class="risk-badge risk-{f.risk_level}">{f.risk_level.upper()}</span></h3>
            <p><strong>Açıklama:</strong> {f.description}</p>
            <p><strong>Etkilenen URL:</strong> <code>{f.affected_url}</code></p>
            <p><strong>Araç:</strong> {f.tool_name}</p>
            <p><strong>CVSS:</strong> {f.cvss_score if f.cvss_score else 'N/A'}</p>
            <details>
                <summary>Kanıt</summary>
                <pre>{json.dumps(f.evidence, indent=2)}</pre>
            </details>
            <details>
                <summary>Nasıl Düzeltilir?</summary>
                <pre>{f.recommendation}</pre>
            </details>
        </div>
        ''' for f in report.findings])}
    </div>
    
    <footer style="text-align: center; margin-top: 40px; color: #666;">
        <p>Generated by WeppenTest Platform v1.0</p>
    </footer>
</body>
</html>
"""
    
    return html


def _generate_markdown_report(report: DetailedReport) -> str:
    """Markdown rapor oluştur"""
    
    md = f"""# 🛡️ WeppenTest Güvenlik Raporu

**Taranan Site:** {report.summary.target_url}  
**Tarama Tarihi:** {report.summary.scan_date.strftime('%Y-%m-%d %H:%M')}  
**Scan ID:** {report.summary.scan_id}

---

## 📊 Özet

- **Toplam Bulgu:** {report.summary.total_findings}
- **Doğrulanmış Bulgular:** {report.summary.verified_findings}
- **Tarama Süresi:** {report.summary.scan_duration_seconds} saniye
- **Kullanılan Araçlar:** {', '.join(report.summary.tools_used)}

### Risk Dağılımı

{chr(10).join([f"- **{f.risk_level.upper()}:** {f.count} (%{f.percentage:.1f})" for f in report.summary.findings_by_risk])}

---

## 🔍 Detaylı Bulgular

{chr(10).join([f'''
### {i+1}. {f.title}

**Risk Seviyesi:** {f.risk_level.upper()}  
**Etkilenen URL:** `{f.affected_url}`  
**Araç:** {f.tool_name}  
**CWE:** {f.cwe_id if f.cwe_id else 'N/A'}  
**CVSS:** {f.cvss_score if f.cvss_score else 'N/A'}  
**Doğrulandı:** {'✅ Evet' if f.verified else '❌ Hayır'}

#### Açıklama
{f.description}

#### Nasıl Düzeltilir?
{f.recommendation}

---
''' for i, f in enumerate(report.findings)])}

## 📋 Öneriler

{chr(10).join([f"{i+1}. {rec}" for i, rec in enumerate(report.recommendations)])}

---

*Generated by WeppenTest Platform v1.0*
"""
    
    return md
