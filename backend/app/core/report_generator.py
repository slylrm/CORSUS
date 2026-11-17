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

    @staticmethod
    def _pdf_line(text: str) -> str:
        replacements = {
            "ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s", "ü": "u",
            "Ç": "C", "Ğ": "G", "İ": "I", "Ö": "O", "Ş": "S", "Ü": "U",
        }
        return "".join(replacements.get(ch, ch) for ch in str(text))
    
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
        .meta { color: #4a5568; margin-top: 8px; }
        .evidence { background: #f7fafc; padding: 10px; border-radius: 8px; margin-top: 10px; white-space: pre-wrap; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #edf2f7; margin-right: 8px; margin-bottom: 8px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ WeppenTest Güvenlik Raporu</h1>
        <p><strong>Site:</strong> {{ data.target_url }}</p>
        <p><strong>Tarih:</strong> {{ data.scan_date }}</p>
        <p><strong>Scan ID:</strong> {{ data.scan_id }}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Özet</h2>
        <p><strong>Toplam Bulgu:</strong> {{ data.total_findings }}</p>
        <p><strong>Doğrulanmış:</strong> {{ data.verified_findings }}</p>
        <p><strong>Tarama Süresi:</strong> {{ data.scan_duration }}s</p>
        <p><strong>Araçlar:</strong> {{ data.tools_used | join(', ') if data.tools_used else '-' }}</p>
        <h3>Risk Dağılımı</h3>
        {% for item in data.risk_distribution %}
          <span class="badge">{{ item.risk_level.upper() }}: {{ item.count }} ({{ '%.1f'|format(item.percentage) }}%)</span>
        {% endfor %}
    </div>

    <div class="summary">
        <h2>🧾 Yönetici Özeti</h2>
        <div class="meta">{{ data.executive_summary | replace('\n', '<br>') | safe }}</div>
        <h3>Öneriler</h3>
        <ul>
        {% for item in data.recommendations %}
          <li>{{ item }}</li>
        {% endfor %}
        </ul>
    </div>
    
    <h2>🔍 Bulgular</h2>
    {% for finding in data.findings %}
    <div class="finding {{ finding.risk_level }}">
        <h3>{{ finding.title }}</h3>
        <p><strong>Risk:</strong> {{ finding.risk_level }}</p>
        <p>{{ finding.description }}</p>
        <p><strong>URL:</strong> <code>{{ finding.affected_url }}</code></p>
        <p><strong>Araç:</strong> {{ finding.tool_name }}</p>
        <p><strong>Doğrulandı:</strong> {{ finding.verified }}</p>
        {% if finding.cwe_id %}<p><strong>CWE:</strong> {{ finding.cwe_id }}</p>{% endif %}
        {% if finding.cvss_score is not none %}<p><strong>CVSS:</strong> {{ finding.cvss_score }}</p>{% endif %}
        <p><strong>İnceleme Zamanı:</strong> {{ finding.found_at }}</p>
        <p><strong>Öneri:</strong> {{ finding.recommendation }}</p>
        <details>
            <summary>Kanıt</summary>
            <div class="evidence">{{ finding.evidence | tojson(indent=2) }}</div>
        </details>
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
    **Süre:** {data.get('scan_duration', 0)}s  
    **Araçlar:** {', '.join(data.get('tools_used', [])) if data.get('tools_used') else '-'}

---

## 📊 Özet

- **Toplam Bulgu:** {data['total_findings']}
- **Doğrulanmış:** {data['verified_findings']}

    ## 📈 Risk Dağılımı

    """

        for item in data.get('risk_distribution', []):
            md_content += f"- **{item['risk_level'].upper()}**: {item['count']} ({item['percentage']:.1f}%)\n"

        md_content += f"""

    ## 🧾 Yönetici Özeti

    {data.get('executive_summary', '').strip()}

    ## ✅ Öneriler

    """

        for recommendation in data.get('recommendations', []):
            md_content += f"- {recommendation}\n"

        md_content += """

---

## 🔍 Bulgular

"""
        
        for i, finding in enumerate(data['findings'], 1):
            md_content += f"""
### {i}. {finding['title']}

**Risk:** {finding['risk_level']}  
**URL:** `{finding['affected_url']}`
    **Araç:** {finding.get('tool_name', '-')}  
    **Doğrulandı:** {finding.get('verified', False)}

    **Açıklama:**

    {finding['description']}

    **Öneri:** {finding.get('recommendation', '-')}

    **Kanıt:**

    ```json
    {json.dumps(finding.get('evidence', {}), ensure_ascii=False, indent=2)}
    ```

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
        """PDF rapor oluştur"""

        lines: List[str] = [
            "WeppenTest Security Report",
            f"Scan ID: {scan_id}",
            f"Target: {data.get('target_url', '-')}",
            f"Scan Date: {data.get('scan_date', '-')}",
            f"Duration: {data.get('scan_duration', 0)}s",
            f"Tools: {', '.join(data.get('tools_used', [])) if data.get('tools_used') else '-'}",
            f"Total Findings: {data.get('total_findings', 0)}",
            f"Verified Findings: {data.get('verified_findings', 0)}",
            "",
            "Risk Distribution:",
        ]

        for item in data.get('risk_distribution', []):
            lines.append(f"- {item['risk_level'].upper()}: {item['count']} ({item['percentage']:.1f}%)")

        executive_summary = str(data.get('executive_summary', '')).strip()
        if executive_summary:
            lines.extend(["", "Executive Summary:", executive_summary])

        recommendations = data.get('recommendations', [])
        if recommendations:
            lines.extend(["", "Recommendations:"])
            for idx, recommendation in enumerate(recommendations, start=1):
                lines.append(f"{idx}. {recommendation}")

        lines.extend(["", "Findings:"])
        for idx, finding in enumerate(data.get('findings', []), start=1):
            lines.append(f"{idx}. [{str(finding.get('risk_level', 'info')).upper()}] {finding.get('title', 'Untitled')}")
            lines.append(f"   Description: {finding.get('description', '-')}")
            lines.append(f"   URL: {finding.get('affected_url', '-')}")
            lines.append(f"   Tool: {finding.get('tool_name', '-')}")
            lines.append(f"   Verified: {finding.get('verified', False)}")
            if finding.get('cwe_id'):
                lines.append(f"   CWE: {finding.get('cwe_id')}")
            if finding.get('cvss_score') is not None:
                lines.append(f"   CVSS: {finding.get('cvss_score')}")
            if finding.get('recommendation'):
                lines.append(f"   Recommendation: {finding.get('recommendation')}")
            evidence = finding.get('evidence') or {}
            if evidence:
                lines.append(f"   Evidence: {json.dumps(evidence, ensure_ascii=False)}")
            lines.append("")

        filepath = self.output_dir / f"report_{scan_id}.pdf"

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas as pdf_canvas

            pdf_bytes = self._build_pdf_from_lines(lines, A4, pdf_canvas)
        except Exception:
            pdf_bytes = self._simple_pdf_bytes(lines)

        with open(filepath, "wb") as f:
            f.write(pdf_bytes)

        self.logger.info(f"PDF report saved: {filepath}")
        return filepath

    def _build_pdf_from_lines(self, lines: List[str], A4: Any, pdf_canvas: Any) -> bytes:
        """Build a PDF using reportlab when available."""
        import io

        buffer = io.BytesIO()
        pdf = pdf_canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        left = 40
        y = height - 45

        def draw_line(text: str, indent: int = 0) -> None:
            nonlocal y
            if y < 45:
                pdf.showPage()
                y = height - 45
            pdf.setFont("Helvetica", 10)
            safe = self._pdf_line(text)
            max_len = 118 - indent // 2
            if max_len < 20:
                max_len = 20
            for i in range(0, len(safe), max_len):
                pdf.drawString(left + indent, y, safe[i:i + max_len])
                y -= 13

        pdf.setTitle("WeppenTest Security Report")
        pdf.setAuthor("WeppenTest")
        for idx, line in enumerate(lines):
            if idx == 0:
                pdf.setFont("Helvetica-Bold", 14)
                draw_line(line)
            else:
                draw_line(line)

        pdf.save()
        buffer.seek(0)
        return buffer.getvalue()

    def _simple_pdf_bytes(self, lines: List[str]) -> bytes:
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
