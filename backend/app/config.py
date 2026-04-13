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


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
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
    DOMAIN_VERIFICATION_REQUIRED: bool = True
    VERIFICATION_TOKEN_PREFIX: str = "weppentest-verify"

    # Tool paths
    TOOLS_BASE_PATH: Optional[Path] = None
    NMAP_PATH: str = "nmap"
    SQLMAP_PATH: str = "sqlmap"
    NIKTO_PATH: str = "nikto"
    HYDRA_PATH: str = "hydra"
    WPSCAN_PATH: str = "wpscan"
    WHATWEB_PATH: str = "whatweb"
    DIRSEARCH_PATH: str = "dirsearch"
    SUBFINDER_PATH: str = "subfinder"
    HTTPX_PATH: str = "httpx"

    # Reporting
    REPORT_OUTPUT_DIR: Path = Path("./reports")
    REPORT_LOGO_PATH: Optional[Path] = None

    # Legal & compliance
    ACCEPT_LEGAL_TERMS_REQUIRED: bool = True
    AUDIT_LOG_ENABLED: bool = True
    GDPR_COMPLIANT: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Optional[Path] = Path("./logs/weppentest.log")

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Any) -> Any:
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
