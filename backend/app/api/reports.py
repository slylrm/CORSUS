"""
Reports API Endpoints
Tarama sonuç raporları
"""

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum
import json

from app.utils.logger import logger
from app.core.scanner import scanner_engine


router = APIRouter()


def _is_verified(finding) -> bool:
    verification_status = getattr(finding, "verification_status", None)
    if verification_status is not None:
        value = getattr(verification_status, "value", verification_status)
        return value == "verified"
    return bool(getattr(finding, "verified", False))


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


@router.get("/{scan_id}/summary", response_model=ReportSummary)
async def get_report_summary(scan_id: str):
    """
    Tarama sonuç özeti
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Yönetici özeti (executive summary)
    """
    
    scan = scanner_engine.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")
    
    # Risk seviyelerine göre bulguları grupla
    findings_by_risk = {}
    for finding in scan.findings:
        risk = finding.risk_level.value
        findings_by_risk[risk] = findings_by_risk.get(risk, 0) + 1
    
    # Yüzdeleri hesapla
    total = len(scan.findings)
    risk_summary = []
    for risk in ["critical", "high", "medium", "low", "info"]:
        count = findings_by_risk.get(risk, 0)
        percentage = (count / total * 100) if total > 0 else 0
        risk_summary.append(FindingSummary(
            risk_level=risk,
            count=count,
            percentage=round(percentage, 1)
        ))
    
    # Scan süresi hesapla
    duration = 0
    if scan.started_at and scan.completed_at:
        duration = int((scan.completed_at - scan.started_at).total_seconds())
    
    return ReportSummary(
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_date=scan.created_at,
        scan_duration_seconds=duration,
        total_findings=len(scan.findings),
        findings_by_risk=risk_summary,
        tools_used=scan.tools,
        verified_findings=sum(1 for f in scan.findings if _is_verified(f)),
        false_positives=0
    )


@router.get("/{scan_id}/detailed", response_model=DetailedReport)
async def get_detailed_report(scan_id: str):
    """
    Detaylı tarama raporu
    
    Args:
        scan_id: Scan ID
        
    Returns:
        Tüm bulgular ve detaylar
    """
    
    scan = scanner_engine.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail=f"Tarama bulunamadı: {scan_id}")
    
    # Özet bilgi
    summary = await get_report_summary(scan_id)
    
    # Bulguları dönüştür
    findings = [
        FindingDetail(
            id=f.id,
            title=f.title,
            description=f.description,
            risk_level=f.risk_level.value,
            affected_url=f.affected_url,
            evidence=f.evidence,
            recommendation=f.recommendation,
            cwe_id=f.cwe_id,
            cvss_score=f.cvss_score,
            verified=_is_verified(f),
            tool_name=f.tool_name,
            found_at=f.found_at
        )
        for f in scan.findings
    ]
    
    # Yönetici özeti oluştur
    critical_count = sum(1 for f in scan.findings if f.risk_level.value == "critical")
    high_count = sum(1 for f in scan.findings if f.risk_level.value == "high")
    
    if critical_count > 0:
        exec_summary = f"⚠️ KRİTİK: {scan.target_url} için yapılan güvenlik taramasında {critical_count} kritik ve {high_count} yüksek riskli güvenlik açığı tespit edildi. Acil müdahale gereklidir."
    elif high_count > 0:
        exec_summary = f"⚠️ YÜKSEK RİSK: {scan.target_url} için yapılan güvenlik taramasında {high_count} yüksek riskli güvenlik açığı tespit edildi. Öncelikli olarak ele alınmalıdır."
    else:
        exec_summary = f"✅ {scan.target_url} için yapılan güvenlik taramasında kritik veya yüksek riskli güvenlik açığı tespit edilmedi. Düşük ve orta seviye bulgular gözden geçirilmelidir."
    
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
    format: ReportFormat = ReportFormat.JSON
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
    detailed_report = await get_detailed_report(scan_id)
    
    if format == ReportFormat.JSON:
        content = json.dumps(detailed_report.model_dump(mode="json"), indent=2, default=str)
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
        # TODO: WeasyPrint ile PDF generate et
        raise HTTPException(status_code=501, detail="PDF export not implemented yet")
    
    elif format == ReportFormat.MARKDOWN:
        # TODO: Markdown format generate et
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
    risk_level: str
):
    """
    Belirli risk seviyesindeki bulguları getir
    
    Args:
        scan_id: Scan ID
        risk_level: Risk seviyesi (critical, high, medium, low, info)
        
    Returns:
        Filtrelenmiş bulgular
    """
    
    # TODO: Risk seviyesine göre filtrele
    
    return {
        "scan_id": scan_id,
        "risk_level": risk_level,
        "findings": []
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
