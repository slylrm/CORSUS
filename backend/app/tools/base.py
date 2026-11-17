"""
Base Tool Wrapper - Enhanced
TÃ¼m pentest araÃ§larÄ±nÄ±n inherit edeceÄŸi base class
UTF-8 encoding fixes, better subprocess handling
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import shutil
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime
from app.utils.logger import logger
try:
    from app.config import PROJECT_ROOT
except Exception:
    PROJECT_ROOT = Path(os.getcwd())


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
    """Standart tool sonuÃ§ formatÄ±"""
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
    """Standart bulgu (aÃ§Ä±k) formatÄ±"""
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
    
    Her pentest aracÄ± bu class'Ä± inherit eder ve
    run(), parse_output(), validate_result() metodlarÄ±nÄ± implemente eder
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
        # Availability flag â€” if binary missing, we won't raise here to allow
        # the scanner to continue and record a per-tool error instead.
        self._available: bool = True
        self._available_reason: Optional[str] = None
        try:
            self._validate_dependencies()
        except RuntimeError as exc:
            self._available = False
            self._available_reason = str(exc)
    
    def _validate_dependencies(self):
        """Tool binary'sinin sisteme kurulu olup olmadÄ±ÄŸÄ±nÄ± kontrol et"""
        configured_path = None
        try:
            from app.config import settings
            configured_path = self.config.get("path") or getattr(settings, f"{self.name.upper()}_PATH", None)
        except Exception:
            configured_path = self.config.get("path")

        binary = configured_path or shutil.which(self.name) or self.name

        def _is_windows_store_alias(path_value: str) -> bool:
            try:
                normalized = os.path.normcase(str(path_value or ""))
                return "\\windowsapps\\" in normalized and normalized.endswith(".exe")
            except Exception:
                return False

        # Windows Store command alias can open Microsoft Store popup.
        if _is_windows_store_alias(str(binary)):
            self.logger.warning(f"{self.name} resolved to Windows Store alias: {binary}")
            raise RuntimeError(f"{self.name} is not installed (Windows Store alias detected)")

        try:
            result = subprocess.run(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                self.logger.warning(f"{self.name} version check failed for {binary}")
        except FileNotFoundError:
            self.logger.error(f"{self.name} not found (checked: {binary})")
            # Raise to allow the caller to decide how to handle missing binaries.
            # Some callers may want to catch this and continue; others may treat
            # it as fatal. Use RuntimeError for compatibility with existing code.
            raise RuntimeError(f"{self.name} is not installed")
        except PermissionError as e:
            self.logger.error(f"{self.name} is not executable (checked: {binary}): {e}")
            raise RuntimeError(f"{self.name} is not executable") from e
        except OSError as e:
            if getattr(e, "winerror", None) == 5:
                self.logger.error(f"{self.name} is not executable (checked: {binary}): {e}")
                raise RuntimeError(f"{self.name} is not executable") from e
            self.logger.warning(f"Could not validate {self.name}: {e}")
        except Exception as e:
            self.logger.warning(f"Could not validate {self.name}: {e}")
    
    @abstractmethod
    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        """
        Tool'u Ã§alÄ±ÅŸtÄ±r
        
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
        Tool Ã§Ä±ktÄ±sÄ±nÄ± parse et ve standart Finding listesine dÃ¶nÃ¼ÅŸtÃ¼r
        
        Args:
            raw_output: Tool'un ham Ã§Ä±ktÄ±sÄ±
            
        Returns:
            List of Finding objects
        """
        pass
    
    def validate_result(self, finding: Finding) -> bool:
        """
        Bulguyu doÄŸrula (false positive kontrolÃ¼)
        
        Args:
            finding: Finding object
            
        Returns:
            True if valid, False if false positive
        """
        # Base implementation - her tool kendi validation'Ä±nÄ± yapabilir
        return True
    
    def _execute_command(
        self,
        command: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Subprocess ile komutu Ã§alÄ±ÅŸtÄ±r (UTF-8 encoding fix)
        
        Args:
            command: Command as list of strings
            timeout: Timeout in seconds
            
        Returns:
            CompletedProcess object with safe UTF-8 decoded output
        """
        def _is_windows_store_alias(path_value: str) -> bool:
            try:
                normalized = os.path.normcase(str(path_value or ""))
                return "\\windowsapps\\" in normalized and normalized.endswith(".exe")
            except Exception:
                return False

        # Resolve command executable to a concrete path where possible
        resolved_executable = None
        original_executable = None
        if command:
            try:
                original_executable = str(command[0])
                # If caller provided a bare name like 'python' or 'py', try to resolve it
                if original_executable and not os.path.isabs(original_executable) and not os.path.exists(original_executable):
                    looked_up = shutil.which(original_executable)
                    if looked_up:
                        resolved_executable = looked_up
                        # replace the first element with the resolved absolute path
                        command = [resolved_executable] + list(command[1:])
                    else:
                        resolved_executable = original_executable
                else:
                    resolved_executable = original_executable
            except Exception:
                resolved_executable = str(command[0])

        # If the resolved executable points to the WindowsApps alias, block it.
        if resolved_executable and _is_windows_store_alias(str(resolved_executable)):
            msg = f"Blocked Windows Store alias execution: {resolved_executable} (original: {original_executable})"
            self.logger.error(msg)
            return subprocess.CompletedProcess(
                args=command,
                returncode=-1,
                stdout="",
                stderr=msg,
            )

        # If caller forgot to provide an executable (e.g. command starts with flags), fail fast with clear message
        try:
            first = command[0] if command else None
            if not first or str(first).startswith("-"):
                msg = f"No executable specified in command: {command}"
                self.logger.error(msg)
                return subprocess.CompletedProcess(args=command, returncode=-1, stdout="", stderr=msg)
        except Exception:
            pass

        # Ensure relative output paths resolve under the repository root
        if not cwd:
            try:
                cwd = str(PROJECT_ROOT)
            except Exception:
                cwd = os.getcwd()

        self.logger.info(f"Executing: {' '.join(command)} | cwd={cwd}")
        
        try:
            runtime_env = env or os.environ.copy()
            # Prevent Python launcher from opening Microsoft Store on missing runtime.
            runtime_env.setdefault("PYLAUNCHER_ALLOW_INSTALL", "0")
            runtime_env.setdefault("PYLAUNCHER_ALWAYS_INSTALL", "0")

            result = subprocess.run(
                command,
                capture_output=True,
                text=False,  # Get bytes
                timeout=timeout,
                check=False,  # Don't raise on non-zero exit
                cwd=cwd,
                env=runtime_env,
            )
            
            # âœ… UTF-8 decode with error handling
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
            
        except subprocess.TimeoutExpired as e:
            # Capture partial output if available and return a CompletedProcess
            try:
                stdout_bytes = e.stdout or b""
                stderr_bytes = e.stderr or b""
            except Exception:
                stdout_bytes = b""
                stderr_bytes = b""

            stdout_safe = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
            stderr_safe = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""

            self.logger.error(f"Command timed out after {timeout}s")

            # Return a CompletedProcess indicating timeout via returncode -1
            return subprocess.CompletedProcess(
                args=e.cmd if hasattr(e, 'cmd') else command,
                returncode=-1,
                stdout=stdout_safe,
                stderr=stderr_safe or f"Command timed out after {timeout}s",
            )
        except PermissionError as e:
            error_message = str(e).strip() or "Permission denied"
            self.logger.error(f"Command execution failed: {error_message}", exc_info=True)
            return subprocess.CompletedProcess(
                args=command,
                returncode=-1,
                stdout="",
                stderr=error_message,
            )
        except OSError as e:
            if getattr(e, "winerror", None) == 5:
                error_message = "[WinError 5] EriÅŸim engellendi"
                self.logger.error(f"Command execution failed: {error_message}", exc_info=True)
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=-1,
                    stdout="",
                    stderr=error_message,
                )
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Tool hakkÄ±nda bilgi dÃ¶ndÃ¼r"""
        return {
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "version": self.version,
            "requires_sudo": self.requires_sudo,
        }

