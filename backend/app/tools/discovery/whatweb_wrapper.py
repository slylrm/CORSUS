"""
WhatWeb Wrapper - Web Technology Fingerprinting
Professional tool wrapper for technology detection

Whatweb is a web technology recognition tool that identifies the technologies
used by a website, including CMS, frameworks, servers, languages, etc.

Fully compatible with ScannerEngine and ToolRunner architecture.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import subprocess
from pathlib import Path

from app.tools.base import (
    BaseToolWrapper,
    ToolResult,
    Finding,
    RiskLevel,
    ToolCategory
)
from app.utils.logger import logger


class WhatWebWrapper(BaseToolWrapper):
    """
    WhatWeb Tool Wrapper - Technology Fingerprinting
    
    Identifies web technologies, frameworks, CMS, servers, languages
    and generates findings for each detected technology.
    
    Features:
    - JSON output parsing
    - Technology categorization
    - Version detection
    - Confidence scoring based on detection certainty
    - False positive minimization
    - Production-ready error handling
    """
    
    name = "whatweb"
    category = ToolCategory.DISCOVERY
    description = "Web technology recognition tool"
    version = "0.5.3"
    requires_sudo = False
    
    # Technology severity mapping
    TECHNOLOGY_SEVERITY = {
        "WordPress": RiskLevel.INFO,
        "Drupal": RiskLevel.INFO,
        "Joomla": RiskLevel.INFO,
        "Magento": RiskLevel.INFO,
        "OpenCart": RiskLevel.INFO,
        "Apache": RiskLevel.INFO,
        "Nginx": RiskLevel.INFO,
        "IIS": RiskLevel.INFO,
        "PHP": RiskLevel.INFO,
        "ASP.NET": RiskLevel.INFO,
        "Node.js": RiskLevel.INFO,
        "Python": RiskLevel.INFO,
        "Java": RiskLevel.INFO,
        "Ruby": RiskLevel.INFO,
        "Perl": RiskLevel.INFO,
        "OpenSSL": RiskLevel.LOW,
        "ModSecurity": RiskLevel.INFO,
        "fail2ban": RiskLevel.INFO,
    }
    
    # Confidence multipliers based on detection method
    CONFIDENCE_MULTIPLIERS = {
        "Meta-Generator": 0.95,        # Usually accurate
        "X-Powered-By": 0.90,          # Usually accurate
        "Server": 0.85,                # Can be spoofed
        "X-AspNet-Version": 0.95,      # Usually accurate
        "Set-Cookie": 0.75,            # Can vary
        "Script": 0.80,                # Library detection
        "HTML": 0.70,                  # Heuristic-based
        "Cookies": 0.60,               # Can be generic
        "Headers": 0.80,               # Usually reliable
        "Interesting-Entries": 0.65,   # Less reliable
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize WhatWeb wrapper"""
        # Don't call super().__init__ to skip dependency check (for testing/demo)
        # In production, set config to enable validation
        self.config = config or {}
        self.whatweb_path = config.get("path", "whatweb") if config else "whatweb"
        self.logger = logger.bind(tool=self.name)
        
        # Optional: validate only if explicitly requested
        if config and config.get("validate_dependencies", False):
            self._validate_dependencies()
    
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Run whatweb against target and return standardized ToolResult
        
        Args:
            target: Target URL (e.g., https://example.com)
            options: Tool-specific options
                {
                    "aggressive": False,  # -a flag: aggressive plugins
                    "custom_headers": {},  # Custom HTTP headers
                    "follow_redirects": True,
                    "user_agent": None,
                    "proxy": None,
                }
        
        Returns:
            ToolResult with parsed findings
        """
        start_time = datetime.now()
        options = options or {}
        
        try:
            self.logger.info(f"Starting whatweb scan on {target}")
            
            # Build command
            command = self._build_command(target, options)
            
            # Execute whatweb
            result = self._execute_command(command)
            
            # Parse output
            findings_data = self._parse_whatweb_output(result.stdout, target)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            self.logger.info(
                f"Whatweb scan completed. "
                f"Found {len(findings_data)} technologies"
            )
            
            return ToolResult(
                tool_name=self.name,
                category=self.category.value,
                target=target,
                timestamp=start_time,
                duration=duration,
                success=True,
                findings=findings_data,
                raw_output=result.stdout,
                errors=[],
                metadata={
                    "technologies_found": len(findings_data),
                    "command": " ".join(command),
                }
            )
            
        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            error_msg = f"Whatweb timeout after {self.config.get('timeout', 300)}s"
            self.logger.error(error_msg)
            return ToolResult(
                tool_name=self.name,
                category=self.category.value,
                target=target,
                timestamp=start_time,
                duration=duration,
                success=False,
                findings=[],
                raw_output="",
                errors=[error_msg],
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            error_msg = f"Whatweb execution failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return ToolResult(
                tool_name=self.name,
                category=self.category.value,
                target=target,
                timestamp=start_time,
                duration=duration,
                success=False,
                findings=[],
                raw_output="",
                errors=[error_msg],
            )
    
    def parse_output(self, raw_output: str) -> List[Finding]:
        """
        Parse whatweb raw output (not used in run() but kept for API compatibility)
        """
        # run() method returns findings directly
        # This method is kept for API compatibility
        return []
    
    def _build_command(self, target: str, options: Dict[str, Any]) -> List[str]:
        """
        Build whatweb command with appropriate flags
        
        Args:
            target: Target URL
            options: Tool options
            
        Returns:
            Command as list of strings
        """
        command = [self.whatweb_path]
        
        # JSON output format (machine-readable)
        command.append("--log=json=/tmp/whatweb_output.json")
        
        # Timeout
        timeout = options.get("timeout", 30)
        command.extend(["--timeout", str(timeout)])
        
        # Aggressive mode (more thorough detection)
        if options.get("aggressive", False):
            command.append("-a")
        
        # Quiet mode (less verbose)
        command.append("-q")
        
        # Follow redirects
        if options.get("follow_redirects", True):
            command.append("--follow-redirect")
        
        # Custom user agent
        user_agent = options.get("user_agent")
        if user_agent:
            command.extend(["--user-agent", user_agent])
        
        # Proxy
        proxy = options.get("proxy")
        if proxy:
            command.extend(["--proxy", proxy])
        
        # Target
        command.append(target)
        
        return command
    
    def _execute_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """
        Execute whatweb command with proper error handling
        
        Args:
            command: Command as list of strings
            
        Returns:
            CompletedProcess with decoded output
        """
        timeout = int(next((cmd for cmd in command if cmd.isdigit()), 300))
        
        self.logger.debug(f"Executing: {' '.join(command[:5])}...")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=False,  # Get bytes first
                timeout=timeout,
                check=False  # Don't raise on non-zero exit
            )
            
            # Safe UTF-8 decoding
            stdout = result.stdout.decode('utf-8', errors='replace') if result.stdout else ""
            stderr = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
            
            if result.returncode != 0 and not stdout:
                self.logger.warning(
                    f"Whatweb exited with code {result.returncode}. "
                    f"Error: {stderr[:200]}"
                )
            
            return subprocess.CompletedProcess(
                args=result.args,
                returncode=result.returncode,
                stdout=stdout,
                stderr=stderr
            )
            
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"Command timed out: {' '.join(command[:3])}")
            raise
    
    def _parse_whatweb_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        """
        Parse whatweb output and extract technologies
        
        Args:
            raw_output: Raw whatweb output (may contain JSON or text)
            target: Target URL
            
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        try:
            # Try to parse JSON output first
            json_data = self._extract_json_from_output(raw_output)
            if json_data:
                findings = self._parse_json_output(json_data, target)
            else:
                # Fallback to text parsing
                findings = self._parse_text_output(raw_output, target)
                
        except Exception as e:
            self.logger.error(f"Error parsing whatweb output: {e}")
            # Return at least some findings from text fallback
            findings = self._parse_text_output(raw_output, target)
        
        # Filter out low-confidence findings
        findings = [f for f in findings if f.get("confidence_score", 0) >= 0.5]
        
        return findings
    
    def _extract_json_from_output(self, raw_output: str) -> Optional[Dict]:
        """
        Extract JSON from whatweb output
        
        Args:
            raw_output: Raw output containing JSON
            
        Returns:
            Parsed JSON dict or None
        """
        try:
            # Try to find JSON in output (between { and })
            start = raw_output.find('{')
            end = raw_output.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = raw_output[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _parse_json_output(self, json_data: Dict, target: str) -> List[Dict[str, Any]]:
        """
        Parse JSON output from whatweb
        
        Args:
            json_data: Parsed JSON data
            target: Target URL
            
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        # Extract plugins/technologies
        plugins = json_data.get("plugins", [])
        
        for plugin_name, plugin_data in plugins.items():
            # Skip plugins with too low confidence
            if not plugin_data:
                continue
            
            # Extract versions and headers
            versions = plugin_data.get("versions", [])
            headers = plugin_data.get("headers", {})
            string = plugin_data.get("string", "")
            
            # Calculate confidence
            confidence = self._calculate_confidence(
                plugin_name,
                versions,
                headers,
                string
            )
            
            # Only include findings with confidence >= 0.5
            if confidence < 0.5:
                continue
            
            # Determine severity
            severity = self.TECHNOLOGY_SEVERITY.get(plugin_name, RiskLevel.INFO)
            
            # Create finding
            finding = {
                "title": f"Web Technology Detected: {plugin_name}",
                "description": self._generate_description(
                    plugin_name, versions, headers, string
                ),
                "risk_level": severity.value,
                "affected_url": target,
                "evidence": {
                    "technology": plugin_name,
                    "versions": versions,
                    "headers": headers,
                    "string": string[:200],  # Limit string length
                },
                "recommendation": self._generate_recommendation(plugin_name),
                "confidence_score": confidence,
                "detection_method": "whatweb_fingerprinting",
            }
            
            findings.append(finding)
        
        return findings
    
    def _parse_text_output(self, raw_output: str, target: str) -> List[Dict[str, Any]]:
        """
        Fallback: Parse text output from whatweb
        
        Args:
            raw_output: Raw text output
            target: Target URL
            
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        # Extract technologies from text lines
        import re

        for line in raw_output.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("http://") or stripped.startswith("https://"):
                for match in re.finditer(r"([A-Za-z0-9_.+-]+)\[([^\]]*)\]", stripped):
                    tech_info = self._parse_text_line(
                        f"{match.group(1)}[{match.group(2)}]",
                        target,
                    )
                    if tech_info:
                        findings.append(tech_info)
                continue

            tech_info = self._parse_text_line(stripped, target)
            if tech_info:
                findings.append(tech_info)
        
        return findings
    
    def _parse_text_line(self, line: str, target: str) -> Optional[Dict[str, Any]]:
        """
        Parse single line from whatweb text output
        
        Args:
            line: Single line from whatweb output
            target: Target URL
            
        Returns:
            Finding dict or None
        """
        # Example line: "WordPress[4.9.8, Entry Point Detection, Meta-Generator]"
        if '[' not in line or ']' not in line:
            return None
        
        try:
            tech_name = line[:line.index('[')].strip()
            details = line[line.index('[') + 1:line.index(']')]
            
            # Skip empty or too generic entries
            if not tech_name or len(tech_name) < 2:
                return None
            
            parts = [p.strip() for p in details.split(',') if p.strip()]
            versions = [p for p in parts if self._is_version(p)]
            detection_methods = [p for p in parts if not self._is_version(p)]

            if not versions and not detection_methods:
                return None
            
            # Calculate confidence based on detection methods
            confidence = self._calculate_confidence_from_methods(detection_methods)
            
            if confidence < 0.5:
                return None
            
            severity = self.TECHNOLOGY_SEVERITY.get(tech_name, RiskLevel.INFO)
            
            return {
                "title": f"Web Technology Detected: {tech_name}",
                "description": f"Detected: {tech_name}. Detection methods: {', '.join(detection_methods)}.",
                "risk_level": severity.value,
                "affected_url": target,
                "evidence": {
                    "technology": tech_name,
                    "versions": versions,
                    "detection_methods": detection_methods,
                },
                "recommendation": self._generate_recommendation(tech_name),
                "confidence_score": confidence,
                "detection_method": "whatweb_fingerprinting",
            }
            
        except Exception as e:
            self.logger.debug(f"Error parsing line: {line}. Error: {e}")
            return None
    
    def _is_version(self, text: str) -> bool:
        """Check if text looks like a version string"""
        import re
        return bool(re.match(r'^\d+(\.\d+)*', text))
    
    def _calculate_confidence(
        self,
        plugin_name: str,
        versions: List[str],
        headers: Dict,
        string: str
    ) -> float:
        """
        Calculate confidence score based on detection data
        
        Args:
            plugin_name: Plugin/technology name
            versions: Detected versions
            headers: Detection headers
            string: Detection strings
            
        Returns:
            Confidence score 0.0-1.0
        """
        confidence = 0.6  # Base confidence
        
        # Version detection increases confidence
        if versions:
            confidence += 0.2
        
        # Multiple detection methods increase confidence
        detection_count = 0
        if headers:
            detection_count += len(headers)
        if string:
            detection_count += 1
        
        if detection_count > 1:
            confidence += 0.15
        
        # Cap at 1.0
        return min(confidence, 1.0)
    
    def _calculate_confidence_from_methods(self, methods: List[str]) -> float:
        """
        Calculate confidence from detection methods
        
        Args:
            methods: List of detection method names
            
        Returns:
            Confidence score 0.0-1.0
        """
        if not methods:
            return 0.5
        
        # Average confidence from known methods
        confidences = []
        for method in methods:
            multiplier = self.CONFIDENCE_MULTIPLIERS.get(method, 0.7)
            confidences.append(multiplier)
        
        if confidences:
            return min(sum(confidences) / len(confidences), 1.0)
        
        return 0.6
    
    def _generate_description(
        self,
        tech_name: str,
        versions: List[str],
        headers: Dict,
        string: str
    ) -> str:
        """Generate finding description"""
        parts = [f"Technology: {tech_name}"]
        
        if versions:
            parts.append(f"Versions: {', '.join(versions)}")
        
        if headers:
            parts.append(f"Detection method: HTTP headers")
        
        if string:
            parts.append(f"Additional info: {string[:100]}")
        
        return ". ".join(parts)
    
    def _generate_recommendation(self, tech_name: str) -> str:
        """Generate security recommendations"""
        recommendations = {
            "WordPress": "Ensure WordPress and all plugins are updated. Remove or secure wp-admin.",
            "Apache": "Keep Apache updated. Disable unnecessary modules.",
            "Nginx": "Keep Nginx updated. Review security configuration.",
            "IIS": "Keep IIS updated. Disable unnecessary features.",
            "PHP": "Keep PHP updated. Use security best practices.",
            "Node.js": "Keep Node.js and dependencies updated.",
            "OpenSSL": "Keep OpenSSL updated for SSL/TLS security.",
            "ModSecurity": "Ensure ModSecurity rules are properly configured.",
        }
        
        return recommendations.get(
            tech_name,
            f"Keep {tech_name} and related components updated and secured."
        )
