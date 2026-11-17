"""
Nmap Wrapper - Network & Port Scanner
"""

from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import re

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.config import settings


class NmapWrapper(BaseToolWrapper):
    """
    Nmap tool wrapper for port scanning and service detection
    """
    
    name = "nmap"
    category = ToolCategory.DISCOVERY
    description = "Network mapper and port scanner"
    version = "7.94"
    requires_sudo = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.nmap_path = config.get("path", settings.NMAP_PATH) if config else settings.NMAP_PATH
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Nmap çalıştır
        
        Args:
            target: Target domain or IP
            options: {
                "scan_type": "fast" | "full" | "vuln",
                "ports": "80,443" or "1-65535",
                "scripts": ["http-headers", "ssl-cert"]
            }
        """
        start_time = datetime.now()
        options = options or {}
        
        scan_type = options.get("scan_type", "fast")
        ports = options.get("ports")
        if isinstance(ports, str):
            ports = ports.strip() or None
        scripts = options.get("scripts", [])
        timeout = int(options.get("timeout", 180))
        
        # XML output için (canonical path from settings)
        xml_output = settings.NMAP_OUTPUT_DIR / f"scan_{datetime.now().timestamp()}.xml"
        xml_output.parent.mkdir(parents=True, exist_ok=True)
        
        # Nmap command
        command = [
            self.nmap_path,
            "-Pn",
            "-sV",  # Service version detection
            "-oX", str(xml_output),  # XML output
            "-oN", "-",  # Normal output to stdout for parser fallback
            "--open",  # Sadece açık portlar
        ]

        if ports:
            command.extend(["-p", str(ports)])
        
        # Scan type'a göre ayarlar
        if scan_type == "fast":
            command.append("-T4")
            # -F cannot be combined with explicit -p ranges.
            if not ports:
                command.append("-F")  # Fast scan, common ports
        elif scan_type == "full":
            command.extend(["-T4", "-A"])  # Aggressive scan
        elif scan_type == "vuln":
            command.extend(["--script", "vuln"])  # Vulnerability scripts
        
        # Custom scripts
        if scripts:
            command.extend(["--script", ",".join(scripts)])
        
        command.append(target)
        
        findings = []
        errors = []
        raw_output = ""
        
        try:
            # Execute Nmap
            result = self._execute_command(command, timeout=timeout)
            raw_output = result.stdout + result.stderr
            
            # Parse XML output
            if xml_output.exists():
                findings = self.parse_xml_output(xml_output)

            if not findings and raw_output:
                self.logger.info("Falling back to Nmap stdout parser for {}", target)
                findings = self.parse_output(raw_output)

            if result.returncode != 0:
                error_detail = (result.stderr or "").strip()
                if not error_detail:
                    output_lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
                    error_detail = output_lines[-1] if output_lines else f"Exit code {result.returncode}"
                errors.append(error_detail[:1000])

            success = result.returncode == 0 or len(findings) > 0
            
        except Exception as e:
            self.logger.error(f"Nmap execution failed: {e}")
            errors.append(str(e))
            success = False
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name=self.name,
            category=self.category.value,
            target=target,
            timestamp=start_time,
            duration=duration,
            success=success,
            findings=[f.to_dict() for f in findings],
            raw_output=raw_output,
            errors=errors,
            metadata={
                "scan_type": scan_type,
                "ports": ports,
                "scripts": scripts,
                "timeout": timeout,
                "command": " ".join(command),
            }
        )
    
    def parse_xml_output(self, xml_file: Path) -> List[Finding]:
        """Parse Nmap XML output"""
        findings = []
        
        try:
            xml_content = xml_file.read_text(encoding="utf-8", errors="replace").strip()
            if not xml_content:
                self.logger.warning(f"Nmap XML output is empty: {xml_file}")
                return findings

            if "</nmaprun>" not in xml_content:
                self.logger.warning(f"Nmap XML output appears truncated: {xml_file}")
                return findings

            tree = ET.ElementTree(ET.fromstring(xml_content))
            root = tree.getroot()
            
            for host in root.findall("host"):
                # Host bilgisi
                address_elem = host.find("address")
                address = address_elem.get("addr") if address_elem is not None else "unknown-host"
                
                # Açık portlar
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = port.get("portid")
                            protocol = port.get("protocol", "tcp")
                            if not port_id:
                                continue
                            
                            service = port.find("service")
                            service_name = service.get("name", "unknown") if service is not None else "unknown"
                            service_version = service.get("version", "") if service is not None else ""
                            
                            # Risk assessment
                            risk_level = self._assess_port_risk(int(port_id), service_name)
                            
                            finding = Finding(
                                title=f"Open Port: {port_id}/{protocol}",
                                description=f"Port {port_id} ({service_name}) açık durumda. "
                                           f"Servis: {service_name} {service_version}",
                                risk_level=risk_level,
                                affected_url=f"{address}:{port_id}",
                                evidence={
                                    "port": port_id,
                                    "protocol": protocol,
                                    "service": service_name,
                                    "version": service_version,
                                    "state": "open"
                                },
                                recommendation=self._get_port_recommendation(int(port_id), service_name),
                                verified=True
                            )
                            
                            findings.append(finding)
            
        except ET.ParseError as e:
            self.logger.warning(f"Failed to parse XML, will rely on stdout fallback: {e}")
        except Exception as e:
            self.logger.error(f"Failed to parse XML: {e}")
        
        return findings
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        """Parse text output as fallback"""
        findings = []
        
        # Simple regex parsing için text output
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)"
        
        for match in re.finditer(port_pattern, raw_output):
            port = match.group(1)
            protocol = match.group(2)
            service = match.group(3)
            
            risk_level = self._assess_port_risk(int(port), service)
            
            finding = Finding(
                title=f"Open Port: {port}/{protocol}",
                description=f"Port {port} ({service}) açık durumda.",
                risk_level=risk_level,
                affected_url=f":{port}",
                evidence={
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                },
                recommendation=self._get_port_recommendation(int(port), service),
                verified=True
            )
            
            findings.append(finding)
        
        return findings
    
    def _assess_port_risk(self, port: int, service: str) -> RiskLevel:
        """Port numarası ve servise göre risk seviyesi belirle"""
        
        # Kritik servisler
        critical_services = ["ftp", "telnet", "smtp", "mysql", "postgresql", "mongodb", "redis"]
        if service.lower() in critical_services:
            return RiskLevel.HIGH
        
        # Yaygın web portları
        if port in [80, 443, 8080, 8443]:
            return RiskLevel.INFO
        
        # Yönetim panelleri
        if port in [22, 3389, 5900]:  # SSH, RDP, VNC
            return RiskLevel.MEDIUM
        
        # Veritabanı portları
        if port in [3306, 5432, 27017, 6379, 1433]:
            return RiskLevel.HIGH
        
        return RiskLevel.LOW
    
    def _get_port_recommendation(self, port: int, service: str) -> str:
        """Port için öneriler"""
        
        if port in [21, 23]:  # FTP, Telnet
            return "⚠️ Bu servis şifrelenmemiş iletişim kullanır. SFTP veya SSH kullanın."
        
        if port == 22:
            return "🔐 SSH güvenliği: Key-based authentication kullanın, root login devre dışı bırakın."
        
        if port in [3306, 5432, 27017]:  # Databases
            return "🗄️ Veritabanı portları internete açık olmamalı. Firewall kuralları ekleyin."
        
        return "✅ Portun gerçekten açık olması gerektiğinden emin olun. Gereksizse kapatın."
