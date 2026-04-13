"""
Report Generator
HTML, PDF, JSON formatlarında rapor oluşturur
"""

from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path
from jinja2 import Template
import json

from app.tools.base import Finding
from app.utils.logger import logger
from app.config import settings


class ReportGenerator:
    """
    Tarama sonuçlarından rapor oluşturan sınıf
    
    Desteklenen formatlar:
    - JSON
    - HTML
    - Markdown
    - PDF (TODO)
    """
    
    def __init__(self):
        self.logger = logger.bind(component="ReportGenerator")
        self.output_dir = settings.REPORT_OUTPUT_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(
        self,
        scan_id: str,
        target_url: str,
        findings: List[Finding],
        metadata: Dict[str, Any],
        format: str = "html"
    ) -> Path:
        """
        Rapor oluştur
        
        Args:
            scan_id: Scan ID
            target_url: Target URL
            findings: Bulgular
            metadata: Ek bilgiler (tools used, duration, etc.)
            format: Rapor formatı
            
        Returns:
            Oluşturulan rapor dosyasının path'i
        """
        
        self.logger.info(f"Generating {format} report for scan: {scan_id}")
        
        report_data = self._prepare_report_data(
            scan_id, target_url, findings, metadata
        )
        
        if format == "json":
            return self._generate_json_report(scan_id, report_data)
        elif format == "html":
            return self._generate_html_report(scan_id, report_data)
        elif format == "markdown":
            return self._generate_markdown_report(scan_id, report_data)
        elif format == "pdf":
            return self._generate_pdf_report(scan_id, report_data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _prepare_report_data(
        self,
        scan_id: str,
        target_url: str,
        findings: List[Finding],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Rapor için veri hazırla"""
        
        # Risk dağılımı
        risk_distribution = self._calculate_risk_distribution(findings)
        
        # Executive summary
        executive_summary = self._generate_executive_summary(
            target_url, findings, risk_distribution
        )
        
        return {
            "scan_id": scan_id,
            "target_url": target_url,
            "scan_date": metadata.get("scan_date", datetime.now()).isoformat(),
            "scan_duration": metadata.get("duration", 0),
            "tools_used": metadata.get("tools_used", []),
            "total_findings": len(findings),
            "verified_findings": sum(1 for f in findings if self._is_verified(f)),
            "risk_distribution": risk_distribution,
            "executive_summary": executive_summary,
            "findings": [f.to_dict() for f in findings],
            "recommendations": self._generate_recommendations(findings),
        }

    @staticmethod
    def _is_verified(finding: Finding) -> bool:
        verification_status = getattr(finding, "verification_status", None)
        if verification_status is not None:
            value = getattr(verification_status, "value", verification_status)
            return value == "verified"
        return bool(getattr(finding, "verified", False))
    
    def _calculate_risk_distribution(
        self, findings: List[Finding]
    ) -> List[Dict[str, Any]]:
        """Risk seviyelerine göre dağılım"""
        
        from collections import Counter
        
        risk_counts = Counter(f.risk_level.value for f in findings)
        total = len(findings) or 1
        
        distribution = []
        for risk_level in ["critical", "high", "medium", "low", "info"]:
            count = risk_counts.get(risk_level, 0)
            distribution.append({
                "risk_level": risk_level,
                "count": count,
                "percentage": (count / total) * 100
            })
        
        return distribution
    
    def _generate_executive_summary(
        self,
        target_url: str,
        findings: List[Finding],
        risk_distribution: List[Dict[str, Any]]
    ) -> str:
        """Yönetici özeti"""
        
        critical_count = next(
            (r["count"] for r in risk_distribution if r["risk_level"] == "critical"),
            0
        )
        high_count = next(
            (r["count"] for r in risk_distribution if r["risk_level"] == "high"),
            0
        )
        
        if critical_count > 0:
            severity = "CRITICAL"
            action = "🔴 DERHAL müdahale gerekiyor!"
        elif high_count > 0:
            severity = "HIGH"
            action = "🟡 En kısa sürede giderilmeli"
        else:
            severity = "LOW"
            action = "🟢 Genel güvenlik durumu iyi"
        
        return f"""
Bu rapor, {target_url} web sitesinin güvenlik taraması sonuçlarını içerir.

**Toplam Bulgu:** {len(findings)}
**Kritik:** {critical_count} | **Yüksek:** {high_count}

**Genel Değerlendirme:** {severity}
**Öncelik:** {action}
"""
    
    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Genel öneriler"""
        
        recommendations = [
            "🔒 Tüm kritik ve yüksek riskli bulguları öncelikli olarak giderin",
            "🔍 Güvenlik taramalarını düzenli olarak tekrarlayın",
            "📚 Geliştirme ekibine güvenli kodlama eğitimleri verin",
        ]
        
        # Bulgulara göre özel öneriler
        if any("sql" in f.title.lower() for f in findings):
            recommendations.append(
                "💉 SQL Injection açıkları için parametreli sorgular kullanın"
            )
        
        if any("xss" in f.title.lower() for f in findings):
            recommendations.append(
                "🔐 XSS koruması için input validation ve output encoding yapın"
            )
        
        return recommendations
    
    def _generate_json_report(
        self, scan_id: str, data: Dict[str, Any]
    ) -> Path:
        """JSON rapor"""
        
        filepath = self.output_dir / f"report_{scan_id}.json"
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"JSON report saved: {filepath}")
        return filepath
    
    def _generate_html_report(
        self, scan_id: str, data: Dict[str, Any]
    ) -> Path:
        """HTML rapor"""
        
        # HTML template
        template_str = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>WeppenTest Report - {{ data.scan_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 30px; border-radius: 10px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; }
        .finding { background: white; padding: 15px; margin: 10px 0; 
                   border-left: 5px solid #ccc; border-radius: 5px; }
        .critical { border-left-color: #e53e3e; }
        .high { border-left-color: #dd6b20; }
        .medium { border-left-color: #d69e2e; }
        .low { border-left-color: #38a169; }
        .info { border-left-color: #3182ce; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WeppenTest Güvenlik Raporu</h1>
        <p><strong>Site:</strong> {{ data.target_url }}</p>
        <p><strong>Tarih:</strong> {{ data.scan_date }}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Özet</h2>
        <p><strong>Toplam Bulgu:</strong> {{ data.total_findings }}</p>
        <p><strong>Doğrulanmış:</strong> {{ data.verified_findings }}</p>
    </div>
    
    <h2>🔍 Bulgular</h2>
    {% for finding in data.findings %}
    <div class="finding {{ finding.risk_level }}">
        <h3>{{ finding.title }}</h3>
        <p><strong>Risk:</strong> {{ finding.risk_level }}</p>
        <p>{{ finding.description }}</p>
        <p><strong>URL:</strong> <code>{{ finding.affected_url }}</code></p>
    </div>
    {% endfor %}
</body>
</html>
"""
        
        template = Template(template_str)
        html_content = template.render(data=data)
        
        filepath = self.output_dir / f"report_{scan_id}.html"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {filepath}")
        return filepath
    
    def _generate_markdown_report(
        self, scan_id: str, data: Dict[str, Any]
    ) -> Path:
        """Markdown rapor"""
        
        md_content = f"""# 🛡️ WeppenTest Güvenlik Raporu

**Site:** {data['target_url']}  
**Tarih:** {data['scan_date']}  
**Scan ID:** {data['scan_id']}

---

## 📊 Özet

- **Toplam Bulgu:** {data['total_findings']}
- **Doğrulanmış:** {data['verified_findings']}

---

## 🔍 Bulgular

"""
        
        for i, finding in enumerate(data['findings'], 1):
            md_content += f"""
### {i}. {finding['title']}

**Risk:** {finding['risk_level']}  
**URL:** `{finding['affected_url']}`

{finding['description']}

---
"""
        
        filepath = self.output_dir / f"report_{scan_id}.md"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        
        self.logger.info(f"Markdown report saved: {filepath}")
        return filepath
    
    def _generate_pdf_report(
        self, scan_id: str, data: Dict[str, Any]
    ) -> Path:
        """PDF rapor (WeasyPrint kullanarak)"""
        
        # TODO: WeasyPrint entegrasyonu
        # HTML'den PDF'e dönüştür
        
        raise NotImplementedError("PDF generation not implemented yet")
