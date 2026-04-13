"""
Built-in Scanner Tool Wrappers
Python-based scanning without external dependencies
"""

import asyncio
import socket
import ssl
import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse

from app.tools.base import BaseToolWrapper, ToolResult, RiskLevel
from app.utils.logger import logger


class BasicInfoWrapper(BaseToolWrapper):
    """Basic information gathering using HTTP requests"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize without dependency validation"""
        self.config = config or {}
        self.logger = logger.bind(tool="basic")
    
    @property
    def name(self) -> str:
        return "basic"
    
    @property
    def display_name(self) -> str:
        return "Basic Info Scanner"
    
    @property
    def description(self) -> str:
        return "Gathers basic information about the target using HTTP requests"
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Not used for async tools"""
        return []
    
    async def run(self, target_url: str, config: Dict[str, Any] = None) -> ToolResult:
        """Run basic info scan"""
        from datetime import datetime
        start_time = datetime.now()
        
        findings = []
        errors = []
        metadata = {}
        
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(target_url)
                    
                    # Server header
                    server = response.headers.get('server', 'Unknown')
                    metadata['server'] = server
                    metadata['status_code'] = response.status_code
                    
                    if server != 'Unknown':
                        findings.append({
                            'title': 'Server Information Disclosure',
                            'description': f'Server header reveals: {server}',
                            'risk_level': RiskLevel.LOW,
                            'affected_url': target_url,
                            'evidence': f'Server: {server}',
                            'recommendation': 'Consider hiding server version information',
                            'cwe_id': 'CWE-200',
                            'confidence_score': 90
                        })
                    
                    # Powered-by headers
                    powered_by = response.headers.get('x-powered-by')
                    if powered_by:
                        findings.append({
                            'title': 'Technology Stack Disclosure',
                            'description': f'X-Powered-By header reveals: {powered_by}',
                            'risk_level': RiskLevel.LOW,
                            'affected_url': target_url,
                            'evidence': f'X-Powered-By: {powered_by}',
                            'recommendation': 'Remove X-Powered-By header',
                            'cwe_id': 'CWE-200',
                            'confidence_score': 95
                        })
                    
                    # Check for common technologies
                    html = response.text.lower()
                    if 'wordpress' in html:
                        findings.append({
                            'title': 'WordPress Detected',
                            'description': 'Site appears to be running WordPress',
                            'risk_level': RiskLevel.INFO,
                            'affected_url': target_url,
                            'evidence': 'WordPress keywords found in HTML',
                            'recommendation': 'Ensure WordPress and plugins are up to date',
                            'confidence_score': 80
                        })
                    
                except httpx.RequestError as e:
                    errors.append(f"HTTP request failed: {str(e)}")
                    
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            logger.error(f"BasicInfo scan error: {e}")
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name="basic",
            category="discovery",
            target=target_url,
            timestamp=start_time,
            duration=duration,
            success=len(errors) == 0,
            findings=findings,
            raw_output=f"Found {len(findings)} findings",
            errors=errors or [],
            metadata=metadata
        )


class SecurityHeadersWrapper(BaseToolWrapper):
    """Security headers scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize without dependency validation"""
        self.config = config or {}
        self.logger = logger.bind(tool="headers")
    
    @property
    def name(self) -> str:
        return "headers"
    
    @property
    def display_name(self) -> str:
        return "Security Headers Scanner"
    
    @property
    def description(self) -> str:
        return "Checks for missing or misconfigured security headers"
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Not used for async tools"""
        return []
    
    async def run(self, target_url: str, config: Dict[str, Any] = None) -> ToolResult:
        """Run security headers scan"""
        from datetime import datetime
        start_time = datetime.now()
        
        findings = []
        errors = []
        metadata = {}
        
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                try:
                    response = await client.get(target_url)
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    # Check for missing security headers
                    security_headers = {
                        'x-frame-options': ('Clickjacking Protection Missing', RiskLevel.MEDIUM, 'CWE-1021'),
                        'x-content-type-options': ('MIME Sniffing Protection Missing', RiskLevel.MEDIUM, 'CWE-430'),
                        'content-security-policy': ('Content Security Policy Missing', RiskLevel.MEDIUM, 'CWE-693'),
                        'strict-transport-security': ('HSTS Missing', RiskLevel.MEDIUM, 'CWE-319'),
                        'x-xss-protection': ('XSS Protection Header Missing', RiskLevel.LOW, 'CWE-79')
                    }
                    
                    for header, (title, risk, cwe) in security_headers.items():
                        if header not in headers:
                            findings.append({
                                'title': title,
                                'description': f'The {header} header is not set',
                                'risk_level': risk,
                                'affected_url': target_url,
                                'evidence': f'Missing header: {header}',
                                'recommendation': f'Add {header} header with appropriate value',
                                'cwe_id': cwe,
                                'confidence_score': 95
                            })
                        else:
                            metadata[header] = headers[header]
                    
                except httpx.RequestError as e:
                    errors.append(f"HTTP request failed: {str(e)}")
                    
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            logger.error(f"SecurityHeaders scan error: {e}")
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name="headers",
            category="discovery",
            target=target_url,
            timestamp=start_time,
            duration=duration,
            success=len(errors) == 0,
            findings=findings,
            raw_output=f"Found {len(findings)} findings",
            errors=errors or [],
            metadata=metadata
        )


class SSLScannerWrapper(BaseToolWrapper):
    """SSL/TLS configuration scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize without dependency validation"""
        self.config = config or {}
        self.logger = logger.bind(tool="ssl")
    
    @property
    def name(self) -> str:
        return "ssl"
    
    @property
    def display_name(self) -> str:
        return "SSL/TLS Scanner"
    
    @property
    def description(self) -> str:
        return "Checks SSL/TLS configuration and certificate validity"
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Not used for async tools"""
        return []
    
    async def run(self, target_url: str, config: Dict[str, Any] = None) -> ToolResult:
        """Run SSL/TLS scan"""
        from datetime import datetime
        start_time = datetime.now()
        
        findings = []
        errors = []
        metadata = {}
        
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if parsed.scheme != 'https':
                findings.append({
                    'title': 'HTTPS Not Used',
                    'description': 'Website does not use HTTPS encryption',
                    'risk_level': RiskLevel.HIGH,
                    'affected_url': target_url,
                    'evidence': f'Protocol: {parsed.scheme}',
                    'recommendation': 'Enable HTTPS for all pages',
                    'cwe_id': 'CWE-319',
                    'confidence_score': 100
                })
            else:
                # Check SSL certificate
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Get SSL version
                            ssl_version = ssock.version()
                            metadata['ssl_version'] = ssl_version
                            
                            # Check for weak protocols
                            if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                findings.append({
                                    'title': 'Weak SSL/TLS Protocol',
                                    'description': f'Server supports weak protocol: {ssl_version}',
                                    'risk_level': RiskLevel.HIGH,
                                    'affected_url': target_url,
                                    'evidence': f'Protocol: {ssl_version}',
                                    'recommendation': 'Disable old SSL/TLS versions, use TLS 1.2+',
                                    'cwe_id': 'CWE-326',
                                    'confidence_score': 95
                                })
                            
                            # Certificate info
                            if cert:
                                metadata['cert_subject'] = dict(x[0] for x in cert['subject'])
                                metadata['cert_issuer'] = dict(x[0] for x in cert['issuer'])
                                
                except ssl.SSLError as e:
                    findings.append({
                        'title': 'SSL Certificate Issue',
                        'description': f'SSL certificate validation failed: {str(e)}',
                        'risk_level': RiskLevel.HIGH,
                        'affected_url': target_url,
                        'evidence': str(e),
                        'recommendation': 'Fix SSL certificate configuration',
                        'cwe_id': 'CWE-295',
                        'confidence_score': 90
                    })
                except Exception as e:
                    errors.append(f"SSL check failed: {str(e)}")
                    
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            logger.error(f"SSL scan error: {e}")
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name="ssl",
            category="discovery",
            target=target_url,
            timestamp=start_time,
            duration=duration,
            success=len(errors) == 0,
            findings=findings,
            raw_output=f"Found {len(findings)} findings",
            errors=errors or [],
            metadata=metadata
        )


class PortScannerWrapper(BaseToolWrapper):
    """Simple port scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize without dependency validation"""
        self.config = config or {}
        self.logger = logger.bind(tool="ports")
    
    @property
    def name(self) -> str:
        return "ports"
    
    @property
    def display_name(self) -> str:
        return "Port Scanner"
    
    @property
    def description(self) -> str:
        return "Scans common ports for open services"
    
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Not used for async tools"""
        return []
    
    async def run(self, target_url: str, config: Dict[str, Any] = None) -> ToolResult:
        """Run port scan"""
        from datetime import datetime
        start_time = datetime.now()
        
        findings = []
        errors = []
        metadata = {}
        
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname
            
            # Common ports to check
            common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
            open_ports = []
            
            async def check_port(port):
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except:
                    return None
            
            # Check ports concurrently
            results = await asyncio.gather(*[check_port(p) for p in common_ports])
            open_ports = [p for p in results if p is not None]
            
            metadata['open_ports'] = open_ports
            
            # Report findings for interesting ports
            interesting_ports = {
                21: ('FTP', RiskLevel.MEDIUM, 'Unencrypted file transfer protocol'),
                22: ('SSH', RiskLevel.INFO, 'Secure shell access'),
                23: ('Telnet', RiskLevel.HIGH, 'Unencrypted remote access'),
                3306: ('MySQL', RiskLevel.MEDIUM, 'Database exposed'),
                3389: ('RDP', RiskLevel.MEDIUM, 'Remote Desktop exposed'),
                5432: ('PostgreSQL', RiskLevel.MEDIUM, 'Database exposed'),
            }
            
            for port in open_ports:
                if port in interesting_ports:
                    service, risk, desc = interesting_ports[port]
                    findings.append({
                        'title': f'{service} Port Open (Port {port})',
                        'description': f'{desc} detected on port {port}',
                        'risk_level': risk,
                        'affected_url': f'{hostname}:{port}',
                        'evidence': f'Open port: {port}',
                        'recommendation': f'Ensure port {port} is properly secured or firewalled',
                        'confidence_score': 90
                    })
                    
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            logger.error(f"Port scan error: {e}")
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            tool_name="ports",
            category="discovery",
            target=target_url,
            timestamp=start_time,
            duration=duration,
            success=len(errors) == 0,
            findings=findings,
            raw_output=f"Found {len(findings)} findings",
            errors=errors or [],
            metadata=metadata
        )
