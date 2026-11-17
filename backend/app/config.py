"""
Application configuration loaded from environment variables and .env.
"""

import json
import warnings
from pathlib import Path
from typing import Any, Optional

import urllib3
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        case_sensitive=True,
        extra="ignore",
        enable_decoding=False,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (
            init_settings,
            dotenv_settings,
            env_settings,
            file_secret_settings,
        )

    # Application
    APP_NAME: str = "WeppenTest Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # API
    API_V1_PREFIX: str = "/api/v1"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./weppentest.db"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # Security
    SECRET_KEY: str = "change-this-in-production-use-openssl-rand-hex-32"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    HTTP_VERIFY_TLS: bool = True
    API_KEY_REQUIRED: bool = False
    API_KEY: Optional[str] = None
    API_KEY_HEADER: str = "X-API-Key"

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_PER_HOUR: int = 1000

    # Scan settings
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT_SECONDS: int = 3600
    MAX_SCAN_DEPTH: int = 3
    RESULTS_RETENTION_DAYS: int = 90

    # Domain verification
    DOMAIN_VERIFICATION_REQUIRED: bool = False
    VERIFICATION_TOKEN_PREFIX: str = "weppentest-verify"

    # Target allow/deny lists (comma-separated or JSON list)
    TARGET_ALLOWLIST: list[str] = []
    TARGET_DENYLIST: list[str] = []

    # Tool paths
    TOOLS_BASE_PATH: Optional[Path] = None
    NMAP_PATH: str = "nmap"
    SQLMAP_PATH: str = "sqlmap"
    NIKTO_PATH: str = "nikto"
    NIKTO_GIT_SOURCE: Optional[str] = None
    PERL_PATH: str = "perl"
    AMASS_PATH: str = "amass"
    NUCLEI_PATH: str = "nuclei"
    WAPITI_PATH: str = "wapiti"
    SEMGREP_PATH: str = "semgrep"
    TRIVY_PATH: str = "trivy"
    GITLEAKS_PATH: str = "gitleaks"
    HYDRA_PATH: str = "hydra"
    WPSCAN_PATH: str = "wpscan"
    WHATWEB_PATH: str = "whatweb"
    DIRSEARCH_PATH: str = "dirsearch"
    SUBFINDER_PATH: str = "subfinder"
    HTTPX_PATH: str = "httpx"
    ZAP_API_URL: str = "http://127.0.0.1:8080"
    ZAP_API_KEY: Optional[str] = None
    METASPLOIT_RPC_URL: Optional[str] = None
    METASPLOIT_RPC_TOKEN: Optional[str] = None
    DEFECTDOJO_URL: Optional[str] = None
    DEFECTDOJO_API_KEY: Optional[str] = None
    FARADAY_URL: Optional[str] = None
    FARADAY_API_KEY: Optional[str] = None
    REPOSITORY_SCAN_PATH: Path = Path(".")

    # Reporting
    REPORT_OUTPUT_DIR: Path = Path("./reports")
    # Tool output directories (relative to project root by default)
    NMAP_OUTPUT_DIR: Path = Path("./nmap_output")
    NUCLEI_OUTPUT_DIR: Path = Path("./nuclei_output")
    NIKTO_OUTPUT_DIR: Path = Path("./nikto_output")
    TRIVY_OUTPUT_DIR: Path = Path("./trivy_output")
    WAPITI_OUTPUT_DIR: Path = Path("./wapiti_output")
    SQLMAP_OUTPUT_DIR: Path = Path("./sqlmap_output")
    SEMGREP_OUTPUT_DIR: Path = Path("./semgrep_output")
    GITLEAKS_OUTPUT_DIR: Path = Path("./gitleaks_output")
    AMASS_OUTPUT_DIR: Path = Path("./amass_output")
    REPORT_LOGO_PATH: Optional[Path] = None

    # Legal & compliance
    ACCEPT_LEGAL_TERMS_REQUIRED: bool = True
    AUDIT_LOG_ENABLED: bool = True
    GDPR_COMPLIANT: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Optional[Path] = Path("./logs/weppentest.log")

    @field_validator("CORS_ORIGINS", "TARGET_ALLOWLIST", "TARGET_DENYLIST", mode="before")
    @classmethod
    def parse_list_settings(cls, value: Any) -> Any:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            raw = value.strip()
            if raw.startswith("["):
                return json.loads(raw)
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value


settings = Settings()

settings.REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
if settings.LOG_FILE:
    settings.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Ensure canonical tool output directories exist under project root
try:
    settings.NMAP_OUTPUT_DIR = PROJECT_ROOT / settings.NMAP_OUTPUT_DIR
    settings.NUCLEI_OUTPUT_DIR = PROJECT_ROOT / settings.NUCLEI_OUTPUT_DIR
    settings.NIKTO_OUTPUT_DIR = PROJECT_ROOT / settings.NIKTO_OUTPUT_DIR
    settings.TRIVY_OUTPUT_DIR = PROJECT_ROOT / settings.TRIVY_OUTPUT_DIR
    settings.WAPITI_OUTPUT_DIR = PROJECT_ROOT / settings.WAPITI_OUTPUT_DIR
    settings.SQLMAP_OUTPUT_DIR = PROJECT_ROOT / settings.SQLMAP_OUTPUT_DIR
    settings.SEMGREP_OUTPUT_DIR = PROJECT_ROOT / settings.SEMGREP_OUTPUT_DIR
    settings.GITLEAKS_OUTPUT_DIR = PROJECT_ROOT / settings.GITLEAKS_OUTPUT_DIR
    settings.AMASS_OUTPUT_DIR = PROJECT_ROOT / settings.AMASS_OUTPUT_DIR

    settings.NMAP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.NUCLEI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.NIKTO_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.TRIVY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.WAPITI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.SQLMAP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.SEMGREP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.GITLEAKS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    settings.AMASS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    # Best-effort; if PROJECT_ROOT resolution fails, ignore and continue
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
