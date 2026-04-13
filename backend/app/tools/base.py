"""
Base Tool Wrapper - Enhanced
Tüm pentest araçlarının inherit edeceği base class
UTF-8 encoding fixes, better subprocess handling
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess
import json
from datetime import datetime
from app.utils.logger import logger


class RiskLevel(str, Enum):
    """Risk seviyeleri"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(str, Enum):
    """Tool kategorileri"""
    DISCOVERY = "discovery"
    INJECTION = "injection"
    AUTH = "authentication"
    MISCONFIGURATION = "misconfiguration"
    CMS = "cms"
    CUSTOM = "custom"


@dataclass
class ToolResult:
    """Standart tool sonuç formatı"""
    tool_name: str
    category: str
    target: str
    timestamp: datetime
    duration: float
    success: bool
    findings: List[Dict[str, Any]]
    raw_output: str
    errors: List[str] = None
    metadata: Dict[str, Any] = None
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    # Progress & quality fields
    progress: Optional[int] = None           # 0-100 tool-level progress if available
    current_action: Optional[str] = None     # High-level step name
    eta_seconds: Optional[float] = None      # Remaining seconds estimate
    evidence_quality_score: Optional[float] = None  # 0-1 subjective quality
    false_positive_likelihood: Optional[float] = None  # 0-1 likelihood
    exploitability_score: Optional[float] = None       # 0-1 ease of exploit
    reproducibility_steps: Optional[List[str]] = None  # Steps to replay finding
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "tool_name": self.tool_name,
            "category": self.category,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "duration": self.duration,
            "success": self.success,
            "findings": self.findings,
            "raw_output": self.raw_output,
            "errors": self.errors or [],
            "metadata": self.metadata or {},
            "exit_code": self.exit_code,
            "progress": self.progress,
            "current_action": self.current_action,
            "eta_seconds": self.eta_seconds,
            "evidence_quality_score": self.evidence_quality_score,
            "false_positive_likelihood": self.false_positive_likelihood,
            "exploitability_score": self.exploitability_score,
            "reproducibility_steps": self.reproducibility_steps,
        }


@dataclass
class Finding:
    """Standart bulgu (açık) formatı"""
    title: str
    description: str
    risk_level: RiskLevel
    affected_url: str
    evidence: Dict[str, Any]
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    verified: bool = False
    evidence_quality_score: Optional[float] = None
    false_positive_likelihood: Optional[float] = None
    exploitability_score: Optional[float] = None
    reproducibility_steps: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "affected_url": self.affected_url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
            "evidence_quality_score": self.evidence_quality_score,
            "false_positive_likelihood": self.false_positive_likelihood,
            "exploitability_score": self.exploitability_score,
            "reproducibility_steps": self.reproducibility_steps,
        }


class BaseToolWrapper(ABC):
    """
    Base class for all tool wrappers
    
    Her pentest aracı bu class'ı inherit eder ve
    run(), parse_output(), validate_result() metodlarını implemente eder
    """
    # Tool metadata (subclass'larda override edilecek)
    name: str = "base_tool"
    category: ToolCategory = ToolCategory.CUSTOM
    description: str = "Base tool wrapper"
    version: str = "1.0.0"
    requires_sudo: bool = False
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize tool wrapper
        
        Args:
            config: Tool-specific configuration
        """
        self.config = config or {}
        self.logger = logger.bind(tool=self.name)
        self._validate_dependencies()
    
    def _validate_dependencies(self):
        """Tool binary'sinin sisteme kurulu olup olmadığını kontrol et"""
        try:
            result = subprocess.run(
                [self.name, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                self.logger.warning(f"{self.name} version check failed")
        except FileNotFoundError:
            self.logger.error(f"{self.name} not found in PATH")
            raise RuntimeError(f"{self.name} is not installed")
        except Exception as e:
            self.logger.warning(f"Could not validate {self.name}: {e}")
    
    @abstractmethod
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Tool'u çalıştır
        
        Args:
            target: Hedef URL veya domain
            options: Tool-specific options
            
        Returns:
            ToolResult object
        """
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Finding]:
        """
        Tool çıktısını parse et ve standart Finding listesine dönüştür
        
        Args:
            raw_output: Tool'un ham çıktısı
            
        Returns:
            List of Finding objects
        """
        pass
    
    def validate_result(self, finding: Finding) -> bool:
        """
        Bulguyu doğrula (false positive kontrolü)
        
        Args:
            finding: Finding object
            
        Returns:
            True if valid, False if false positive
        """
        # Base implementation - her tool kendi validation'ını yapabilir
        return True
    
    def _execute_command(
        self,
        command: List[str],
        timeout: int = 300
    ) -> subprocess.CompletedProcess:
        """
        Subprocess ile komutu çalıştır (UTF-8 encoding fix)
        
        Args:
            command: Command as list of strings
            timeout: Timeout in seconds
            
        Returns:
            CompletedProcess object with safe UTF-8 decoded output
        """
        self.logger.info(f"Executing: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=False,  # Get bytes
                timeout=timeout,
                check=False  # Don't raise on non-zero exit
            )
            
            # ✅ UTF-8 decode with error handling
            stdout_safe = result.stdout.decode('utf-8', errors='replace') if result.stdout else ""
            stderr_safe = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
            
            # Log execution
            self.logger.info(
                f"Command completed | Exit: {result.returncode} | "
                f"Output: {len(stdout_safe)} bytes"
            )
            
            # Create safe result object
            safe_result = subprocess.CompletedProcess(
                args=result.args,
                returncode=result.returncode,
                stdout=stdout_safe,
                stderr=stderr_safe
            )
            
            return safe_result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {timeout}s")
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Tool hakkında bilgi döndür"""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "version": self.version,
            "requires_sudo": self.requires_sudo,
        }
