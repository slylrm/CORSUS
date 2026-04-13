"""
Technology Fingerprint Wrapper
Collects headers, TLS hints (when HTTPS), cookies and favicon hash.
"""

import hashlib
import ssl
import socket
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.tools.base import BaseToolWrapper, RiskLevel, ToolResult
from app.config import settings
from app.utils.logger import logger


class TechFingerprintWrapper(BaseToolWrapper):
    name = "fingerprint"
    category = "discovery"
    description = "HTTP header and favicon fingerprinting"
    requires_sudo = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logger.bind(tool=self.name)

    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        return []

    async def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> ToolResult:
        opts = options or {}
        start_ts = datetime.now()
        timeout = int(opts.get("timeout", 20))

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(target)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                metadata["headers"] = headers
                server = headers.get("server")
                x_powered = headers.get("x-powered-by")
                if server:
                    findings.append({
                        "title": "Server banner disclosed",
                        "description": f"Server header exposes: {server}",
                        "risk_level": RiskLevel.LOW,
                        "affected_url": target,
                        "evidence": {"server": server},
                        "recommendation": "Minimize server banner exposure",
                        "confidence_score": 0.78,
                    })
                if x_powered:
                    findings.append({
                        "title": "Framework disclosed",
                        "description": f"X-Powered-By exposes: {x_powered}",
                        "risk_level": RiskLevel.LOW,
                        "affected_url": target,
                        "evidence": {"x_powered_by": x_powered},
                        "recommendation": "Remove X-Powered-By header",
                        "confidence_score": 0.8,
                    })
                # Favicon hash (murmur not needed; SHA1 ok)
                try:
                    fav_url = target.rstrip('/') + "/favicon.ico"
                    fav_resp = await client.get(fav_url)
                    if fav_resp.status_code == 200 and fav_resp.content:
                        sha1 = hashlib.sha1(fav_resp.content).hexdigest()
                        metadata["favicon_sha1"] = sha1
                        findings.append({
                            "title": "Favicon fingerprint collected",
                            "description": "Favicon hash can identify frameworks/products",
                            "risk_level": RiskLevel.INFO,
                            "affected_url": fav_url,
                            "evidence": {"favicon_sha1": sha1},
                            "recommendation": "Be aware of passive fingerprinting",
                            "confidence_score": 0.65,
                        })
                except Exception as exc:  # noqa: BLE001
                    errors.append(str(exc))
                # TLS info if HTTPS
                parsed = urlparse(target)
                if parsed.scheme == "https":
                    try:
                        ctx = ssl.create_default_context()
                        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=5) as sock:
                            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                                cipher = ssock.cipher()
                                tls_version = ssock.version()
                                metadata["tls_cipher"] = cipher
                                metadata["tls_version"] = tls_version
                                if tls_version in ["TLSv1", "TLSv1.1"]:
                                    findings.append({
                                        "title": "Weak TLS version supported",
                                        "description": f"Server negotiated {tls_version}",
                                        "risk_level": RiskLevel.HIGH,
                                        "affected_url": target,
                                        "evidence": {"tls_version": tls_version, "cipher": cipher},
                                        "recommendation": "Disable legacy TLS and enforce TLS1.2+",
                                        "confidence_score": 0.9,
                                    })
                    except Exception as exc:  # noqa: BLE001
                        errors.append(str(exc))
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
            self.logger.error("Fingerprint error", exc_info=True)

        duration = (datetime.now() - start_ts).total_seconds()

        return ToolResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            timestamp=start_ts,
            duration=duration,
            success=len(errors) == 0 or len(findings) > 0,
            findings=findings,
            raw_output=f"findings={len(findings)}",
            errors=errors,
            metadata=metadata,
        )


def insert_single_fingerprint_finding(scan_id: str, tool_result: Dict[str, Any]) -> None:
    """
    Insert all fingerprint findings into the findings table (one row per finding).

    Mapping rules (exact):
    - title <- finding["title"]
    - description <- finding["description"]
    - risk_level <- string
    - affected_url <- finding["affected_url"]
    - tool_name <- "fingerprint"
    - evidence <- JSON string
    - recommendation <- finding["recommendation"]
    - confidence_score <- finding["confidence_score"]
    - found_at <- ToolResult.timestamp
    - other fields: fixed/NULL
    """
    findings = tool_result.get("findings") or []
    if not findings:
        logger.warning("[FINGERPRINT][DB] No findings to insert")
        return

    timestamp = tool_result.get("timestamp")
    found_at = timestamp if isinstance(timestamp, str) else datetime.now().isoformat()

    db_path = settings.DATABASE_URL.split("///")[-1]
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        for finding in findings:
            risk_level = str(finding.get("risk_level", "info"))
            evidence_json = json.dumps(finding.get("evidence", {}), ensure_ascii=False)
            sources_json = json.dumps(["fingerprint"], ensure_ascii=False)

            row = {
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "title": finding.get("title"),
                "description": finding.get("description"),
                "risk_level": risk_level,
                "affected_url": finding.get("affected_url"),
                "tool_name": "fingerprint",
                "evidence": evidence_json,
                "recommendation": finding.get("recommendation"),
                "cwe_id": None,
                "cvss_score": None,
                "confidence_score": finding.get("confidence_score"),
                "verification_status": "unverified",
                "sources": sources_json,
                "detection_method": "automated",
                "low_confidence_reason": None,
                "is_low_confidence": 0,
                "is_heuristic": 0,
                "found_at": found_at,
            }

            cursor.execute(
                """
                INSERT INTO findings (
                    id, scan_id, title, description, risk_level, affected_url,
                    tool_name, evidence, recommendation, cwe_id, cvss_score,
                    confidence_score, verification_status, sources,
                    detection_method, low_confidence_reason,
                    is_low_confidence, is_heuristic, found_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["scan_id"],
                    row["title"],
                    row["description"],
                    row["risk_level"],
                    row["affected_url"],
                    row["tool_name"],
                    row["evidence"],
                    row["recommendation"],
                    row["cwe_id"],
                    row["cvss_score"],
                    row["confidence_score"],
                    row["verification_status"],
                    row["sources"],
                    row["detection_method"],
                    row["low_confidence_reason"],
                    row["is_low_confidence"],
                    row["is_heuristic"],
                    row["found_at"],
                ),
            )

        conn.commit()
        logger.info(f"[FINGERPRINT][DB] Inserted {len(findings)} findings scan_id={scan_id}")
        print(f"[FINGERPRINT][DB] Inserted {len(findings)} findings scan_id={scan_id}")
    finally:
        conn.close()
