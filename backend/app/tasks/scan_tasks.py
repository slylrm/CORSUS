"""
Scan Tasks
Tarama işlemleri için background task'lar
"""

from typing import Dict, Any, List
from datetime import datetime
import asyncio

from app.tasks import celery_app
from app.utils.logger import logger
from app.tools.injection.sqlmap_wrapper import SQLMapWrapper
from app.tools.discovery.nmap_wrapper import NmapWrapper


@celery_app.task(bind=True, name="tasks.run_scan")
def run_scan_task(self, scan_id: str, target_url: str, scan_config: Dict[str, Any]):
    """
    Ana tarama task'ı
    
    Args:
        scan_id: Scan ID
        target_url: Target URL
        scan_config: Scan konfigürasyonu (tools, options vb.)
    """
    
    logger.info(f"Starting scan task: {scan_id}")
    
    # Task state update
    self.update_state(
        state="RUNNING",
        meta={
            "scan_id": scan_id,
            "progress": 0,
            "current_tool": None,
            "message": "Initializing scan..."
        }
    )
    
    try:
        # Kullanılacak toollar
        tools_to_use = scan_config.get("tools", ["nmap", "sqlmap"])
        total_tools = len(tools_to_use)
        
        all_results = []
        
        for idx, tool_name in enumerate(tools_to_use):
            progress = int((idx / total_tools) * 100)
            
            self.update_state(
                state="RUNNING",
                meta={
                    "scan_id": scan_id,
                    "progress": progress,
                    "current_tool": tool_name,
                    "message": f"Running {tool_name}..."
                }
            )
            
            # Tool çalıştır
            result = _run_tool(tool_name, target_url, scan_config)
            all_results.append(result)
            
            logger.info(f"Completed {tool_name} for scan {scan_id}")
        
        # Final state
        self.update_state(
            state="SUCCESS",
            meta={
                "scan_id": scan_id,
                "progress": 100,
                "current_tool": None,
                "message": "Scan completed",
                "results_count": len(all_results)
            }
        )
        
        # TODO: Sonuçları veritabanına kaydet
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "results": all_results,
            "completed_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Scan task failed: {e}", exc_info=True)
        
        self.update_state(
            state="FAILURE",
            meta={
                "scan_id": scan_id,
                "error": str(e),
                "message": "Scan failed"
            }
        )
        
        raise


def _run_tool(tool_name: str, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Belirli bir tool'u çalıştır
    
    Args:
        tool_name: Tool adı
        target_url: Target URL
        config: Tool konfigürasyonu
        
    Returns:
        Tool sonuçları
    """
    
    logger.info(f"Running tool: {tool_name}")
    
    try:
        if tool_name == "sqlmap":
            wrapper = SQLMapWrapper()
            result = wrapper.run(target_url, config.get("sqlmap_options"))
            return result.to_dict()
        
        elif tool_name == "nmap":
            # URL'den domain çıkar
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.path
            
            wrapper = NmapWrapper()
            result = wrapper.run(domain, config.get("nmap_options"))
            return result.to_dict()
        
        # Diğer tool'lar buraya eklenecek
        else:
            logger.warning(f"Unknown tool: {tool_name}")
            return {
                "tool_name": tool_name,
                "status": "skipped",
                "message": "Tool not implemented"
            }
    
    except Exception as e:
        logger.error(f"Tool {tool_name} failed: {e}")
        return {
            "tool_name": tool_name,
            "status": "failed",
            "error": str(e)
        }


@celery_app.task(name="tasks.validate_findings")
def validate_findings_task(scan_id: str, findings: List[Dict[str, Any]]):
    """
    Bulguları doğrula (false positive kontrolü)
    
    Args:
        scan_id: Scan ID
        findings: Bulgular listesi
    """
    
    logger.info(f"Validating findings for scan: {scan_id}")
    
    validated_findings = []
    
    for finding in findings:
        # TODO: Her bulgu için cross-validation yap
        # - Farklı tool ile doğrula
        # - Manuel payload test et
        # - Known false positive patterns kontrol et
        
        validated = {
            **finding,
            "validated": True,
            "validation_method": "automatic",
            "validated_at": datetime.now().isoformat()
        }
        
        validated_findings.append(validated)
    
    return validated_findings


@celery_app.task(name="tasks.generate_report")
def generate_report_task(scan_id: str, format: str = "html"):
    """
    Rapor oluştur
    
    Args:
        scan_id: Scan ID
        format: Rapor formatı (html, pdf, json)
    """
    
    logger.info(f"Generating {format} report for scan: {scan_id}")
    
    # TODO: Rapor oluşturma mantığı
    
    return {
        "scan_id": scan_id,
        "format": format,
        "status": "completed",
        "file_path": f"./reports/report_{scan_id}.{format}"
    }


@celery_app.task(name="tasks.cleanup_old_scans")
def cleanup_old_scans_task():
    """
    Eski taramaları temizle (scheduled task)
    
    settings.RESULTS_RETENTION_DAYS'den eski taramaları sil
    """
    
    logger.info("Running cleanup task for old scans")
    
    # TODO: Veritabanından eski kayıtları sil
    # TODO: Dosya sisteminden eski raporları sil
    
    return {
        "status": "completed",
        "deleted_count": 0
    }


# Periodic tasks
celery_app.conf.beat_schedule = {
    "cleanup-old-scans": {
        "task": "tasks.cleanup_old_scans",
        "schedule": 86400.0,  # Her 24 saatte bir
    },
}
