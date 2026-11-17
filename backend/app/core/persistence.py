"""
SQLite persistence helpers for scan lifecycle, tool executions, findings, and verification tokens.

This module intentionally uses direct sqlite3 access to keep API/runtime usage lightweight.
All operations are best-effort: failures are logged and swallowed unless explicitly required.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from app.config import settings
from app.utils.logger import logger


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _db_path() -> Path:
    raw_path = settings.DATABASE_URL.split("///")[-1]
    path = Path(raw_path)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _json_dumps(value: Any, default: str = "{}") -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return default


def _json_loads(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return default


def get_connection() -> sqlite3.Connection:
    db_path = _db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _verification_status_value(finding: Any) -> str:
    status_obj = getattr(finding, "verification_status", None)
    if status_obj is None and isinstance(finding, dict):
        status_obj = finding.get("verification_status")

    if status_obj is None:
        return "unverified"

    value = getattr(status_obj, "value", status_obj)
    return str(value)


def _risk_level_value(finding: Any) -> str:
    risk_obj = getattr(finding, "risk_level", None)
    if risk_obj is None and isinstance(finding, dict):
        risk_obj = finding.get("risk_level")
    value = getattr(risk_obj, "value", risk_obj)
    return str(value or "info")


def upsert_scan_state(scan: Any, extra: Optional[Dict[str, Any]] = None) -> None:
    """Persist the current scan state into the scans table."""
    extra = extra or {}

    try:
        findings = list(getattr(scan, "findings", []) or [])
        verified_count = sum(1 for f in findings if _verification_status_value(f) == "verified")
        needs_review_count = sum(
            1 for f in findings if _verification_status_value(f) == "needs_manual_verification"
        )

        status_obj = extra.get("status", getattr(scan, "status", "pending"))
        status = getattr(status_obj, "value", status_obj)

        row = {
            "scan_id": getattr(scan, "scan_id", extra.get("scan_id")),
            "owner_id": extra.get("owner_id", getattr(scan, "owner_id", None)),
            "target_url": extra.get("target_url", getattr(scan, "target_url", "")),
            "scan_type": extra.get("scan_type", getattr(scan, "scan_type", "quick")),
            "status": str(status or "pending"),
            "progress": int(extra.get("progress", getattr(scan, "progress", 0) or 0)),
            "current_phase": extra.get("current_phase", getattr(scan, "current_phase", None)),
            "current_tool": extra.get("current_tool", getattr(scan, "current_tool", None)),
            "tools_json": _json_dumps(extra.get("tools", getattr(scan, "tools", [])), default="[]"),
            "findings_count": int(extra.get("findings_count", len(findings))),
            "findings_verified": int(extra.get("findings_verified", verified_count)),
            "findings_needs_review": int(extra.get("findings_needs_review", needs_review_count)),
            "correlated_risks_json": _json_dumps(
                extra.get("correlated_risks", getattr(scan, "correlated_risks", [])),
                default="[]",
            ),
            "report_summary_json": _json_dumps(
                extra.get("report_summary", getattr(scan, "report_summary", {})),
                default="{}",
            ),
            "authorization_acknowledged": int(
                bool(extra.get("authorization_acknowledged", getattr(scan, "authorization_acknowledged", False)))
            ),
            "scope_statement": extra.get("scope_statement", getattr(scan, "scope_statement", None)),
            "error_message": extra.get("error_message", getattr(scan, "error_message", None)),
            "error_type": extra.get("error_type", None),
            "error_tool": extra.get("error_tool", None),
            "error_stage": extra.get("error_stage", None),
            "technical_reason": extra.get("technical_reason", None),
            "error_hint": extra.get("error_hint", None),
            "waf_detected": int(bool(extra.get("waf_detected", getattr(scan, "waf_detected", False)))),
            "waf_vendor": extra.get("waf_vendor", getattr(scan, "waf_vendor", None)),
            "waf_confidence_score": float(
                extra.get("waf_confidence_score", getattr(scan, "waf_confidence_score", 0.0) or 0.0)
            ),
            "rate_limit_detected": int(
                bool(extra.get("rate_limit_detected", getattr(scan, "rate_limit_detected", False)))
            ),
            "bot_protection_detected": int(
                bool(extra.get("bot_protection_detected", getattr(scan, "bot_protection_detected", False)))
            ),
            "created_at": _to_iso(extra.get("created_at", getattr(scan, "created_at", None))),
            "started_at": _to_iso(extra.get("started_at", getattr(scan, "started_at", None))),
            "completed_at": _to_iso(extra.get("completed_at", getattr(scan, "completed_at", None))),
            "updated_at": _utc_now_iso(),
        }

        if not row["scan_id"]:
            logger.warning("Skipping scan persistence due to missing scan_id")
            return

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, owner_id, target_url, scan_type, status, progress,
                    current_phase, current_tool, tools_json,
                    findings_count, findings_verified, findings_needs_review,
                    correlated_risks_json, report_summary_json,
                    authorization_acknowledged, scope_statement,
                    error_message, error_type, error_tool, error_stage,
                    technical_reason, error_hint,
                    waf_detected, waf_vendor, waf_confidence_score,
                    rate_limit_detected, bot_protection_detected,
                    created_at, started_at, completed_at, updated_at
                ) VALUES (
                    :scan_id, :owner_id, :target_url, :scan_type, :status, :progress,
                    :current_phase, :current_tool, :tools_json,
                    :findings_count, :findings_verified, :findings_needs_review,
                    :correlated_risks_json, :report_summary_json,
                    :authorization_acknowledged, :scope_statement,
                    :error_message, :error_type, :error_tool, :error_stage,
                    :technical_reason, :error_hint,
                    :waf_detected, :waf_vendor, :waf_confidence_score,
                    :rate_limit_detected, :bot_protection_detected,
                    :created_at, :started_at, :completed_at, :updated_at
                )
                ON CONFLICT(scan_id) DO UPDATE SET
                    owner_id=excluded.owner_id,
                    target_url=excluded.target_url,
                    scan_type=excluded.scan_type,
                    status=excluded.status,
                    progress=excluded.progress,
                    current_phase=excluded.current_phase,
                    current_tool=excluded.current_tool,
                    tools_json=excluded.tools_json,
                    findings_count=excluded.findings_count,
                    findings_verified=excluded.findings_verified,
                    findings_needs_review=excluded.findings_needs_review,
                    correlated_risks_json=excluded.correlated_risks_json,
                    report_summary_json=excluded.report_summary_json,
                    authorization_acknowledged=excluded.authorization_acknowledged,
                    scope_statement=excluded.scope_statement,
                    error_message=excluded.error_message,
                    error_type=excluded.error_type,
                    error_tool=excluded.error_tool,
                    error_stage=excluded.error_stage,
                    technical_reason=excluded.technical_reason,
                    error_hint=excluded.error_hint,
                    waf_detected=excluded.waf_detected,
                    waf_vendor=excluded.waf_vendor,
                    waf_confidence_score=excluded.waf_confidence_score,
                    rate_limit_detected=excluded.rate_limit_detected,
                    bot_protection_detected=excluded.bot_protection_detected,
                    started_at=excluded.started_at,
                    completed_at=excluded.completed_at,
                    updated_at=excluded.updated_at
                """,
                row,
            )
            conn.commit()
    except Exception:
        logger.warning("Scan state persistence failed", exc_info=True)


def persist_scan_findings(scan_id: str, findings: Iterable[Any]) -> None:
    """Replace all findings for a scan with the provided set."""
    try:
        rows: List[Dict[str, Any]] = []
        for finding in findings or []:
            if isinstance(finding, dict):
                finding_dict = finding
            else:
                finding_dict = {
                    "id": getattr(finding, "id", str(uuid.uuid4())),
                    "title": getattr(finding, "title", "Unknown"),
                    "description": getattr(finding, "description", ""),
                    "risk_level": _risk_level_value(finding),
                    "affected_url": getattr(finding, "affected_url", ""),
                    "tool_name": getattr(finding, "tool_name", "unknown"),
                    "evidence": getattr(finding, "evidence", {}),
                    "recommendation": getattr(finding, "recommendation", ""),
                    "cwe_id": getattr(finding, "cwe_id", None),
                    "cvss_score": getattr(finding, "cvss_score", None),
                    "confidence_score": getattr(finding, "confidence_score", 1.0),
                    "verification_status": _verification_status_value(finding),
                    "sources": getattr(finding, "sources", []),
                    "detection_method": getattr(finding, "detection_method", "automated"),
                    "low_confidence_reason": getattr(finding, "low_confidence_reason", None),
                    "is_low_confidence": bool(getattr(finding, "is_low_confidence", False)),
                    "is_heuristic": bool(getattr(finding, "is_heuristic", False)),
                    "found_at": _to_iso(getattr(finding, "found_at", None)) or _utc_now_iso(),
                }

            rows.append(
                {
                    "id": finding_dict.get("id") or str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "title": finding_dict.get("title") or "Unknown",
                    "description": finding_dict.get("description"),
                    "risk_level": str(finding_dict.get("risk_level") or "info"),
                    "affected_url": finding_dict.get("affected_url"),
                    "tool_name": finding_dict.get("tool_name") or "unknown",
                    "evidence": _json_dumps(finding_dict.get("evidence", {}), default="{}"),
                    "recommendation": finding_dict.get("recommendation"),
                    "cwe_id": finding_dict.get("cwe_id"),
                    "cvss_score": finding_dict.get("cvss_score"),
                    "confidence_score": float(finding_dict.get("confidence_score") or 0.0),
                    "verification_status": str(finding_dict.get("verification_status") or "unverified"),
                    "sources": _json_dumps(finding_dict.get("sources", []), default="[]"),
                    "detection_method": finding_dict.get("detection_method") or "automated",
                    "low_confidence_reason": finding_dict.get("low_confidence_reason"),
                    "is_low_confidence": int(bool(finding_dict.get("is_low_confidence", False))),
                    "is_heuristic": int(bool(finding_dict.get("is_heuristic", False))),
                    "found_at": finding_dict.get("found_at") or _utc_now_iso(),
                }
            )

        with get_connection() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            if rows:
                conn.executemany(
                    """
                    INSERT INTO findings (
                        id, scan_id, title, description, risk_level, affected_url,
                        tool_name, evidence, recommendation, cwe_id, cvss_score,
                        confidence_score, verification_status, sources,
                        detection_method, low_confidence_reason,
                        is_low_confidence, is_heuristic, found_at
                    ) VALUES (
                        :id, :scan_id, :title, :description, :risk_level, :affected_url,
                        :tool_name, :evidence, :recommendation, :cwe_id, :cvss_score,
                        :confidence_score, :verification_status, :sources,
                        :detection_method, :low_confidence_reason,
                        :is_low_confidence, :is_heuristic, :found_at
                    )
                    """,
                    rows,
                )
            conn.commit()
    except Exception:
        logger.warning("Finding persistence failed for scan {}", scan_id, exc_info=True)


def append_tool_execution(
    *,
    scan_id: str,
    tool_name: str,
    target: Optional[str],
    status: str,
    exit_code: Optional[int],
    execution_time_seconds: Optional[float],
    stdout: Optional[str],
    stderr: Optional[str],
    findings_count: int = 0,
    error_message: Optional[str] = None,
) -> None:
    """Persist one tool execution record."""
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tool_executions (
                    id, scan_id, tool_name, target, status,
                    exit_code, execution_time_seconds,
                    stdout, stderr, findings_count,
                    error_message, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    scan_id,
                    tool_name,
                    target,
                    status,
                    exit_code,
                    execution_time_seconds,
                    (stdout or "")[:12000],
                    (stderr or "")[:12000],
                    int(findings_count),
                    error_message,
                    _utc_now_iso(),
                ),
            )
            conn.commit()
    except Exception:
        logger.warning("Tool execution persistence failed for {}", tool_name, exc_info=True)


def _scan_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    data["tools"] = _json_loads(data.pop("tools_json", "[]"), [])
    data["correlated_risks"] = _json_loads(data.pop("correlated_risks_json", "[]"), [])
    data["report_summary"] = _json_loads(data.pop("report_summary_json", "{}"), {})
    data["authorization_acknowledged"] = bool(data.get("authorization_acknowledged"))
    data["waf_detected"] = bool(data.get("waf_detected"))
    data["rate_limit_detected"] = bool(data.get("rate_limit_detected"))
    data["bot_protection_detected"] = bool(data.get("bot_protection_detected"))
    return data


def get_scan_record(scan_id: str, owner_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    try:
        with get_connection() as conn:
            if owner_id:
                row = conn.execute(
                    "SELECT * FROM scans WHERE scan_id = ? AND owner_id = ?",
                    (scan_id, owner_id),
                ).fetchone()
            else:
                row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            return _scan_row_to_dict(row)
    except Exception:
        logger.warning("Failed to load scan record {}", scan_id, exc_info=True)
        return None


def list_scan_records(
    status: Optional[str],
    limit: int,
    offset: int,
    owner_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    try:
        with get_connection() as conn:
            if status:
                if owner_id:
                    rows = conn.execute(
                        """
                        SELECT * FROM scans
                        WHERE LOWER(status) = LOWER(?) AND owner_id = ?
                        ORDER BY datetime(created_at) DESC
                        LIMIT ? OFFSET ?
                        """,
                        (status, owner_id, limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM scans
                        WHERE LOWER(status) = LOWER(?)
                        ORDER BY datetime(created_at) DESC
                        LIMIT ? OFFSET ?
                        """,
                        (status, limit, offset),
                    ).fetchall()
            else:
                if owner_id:
                    rows = conn.execute(
                        """
                        SELECT * FROM scans
                        WHERE owner_id = ?
                        ORDER BY datetime(created_at) DESC
                        LIMIT ? OFFSET ?
                        """,
                        (owner_id, limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM scans
                        ORDER BY datetime(created_at) DESC
                        LIMIT ? OFFSET ?
                        """,
                        (limit, offset),
                    ).fetchall()
        return [_scan_row_to_dict(r) for r in rows]
    except Exception:
        logger.warning("Failed to list scan records", exc_info=True)
        return []


def get_findings_for_scan(scan_id: str, risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        with get_connection() as conn:
            if risk_level:
                rows = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE scan_id = ? AND LOWER(risk_level) = LOWER(?)
                    ORDER BY datetime(found_at) DESC
                    """,
                    (scan_id, risk_level),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE scan_id = ?
                    ORDER BY datetime(found_at) DESC
                    """,
                    (scan_id,),
                ).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["evidence"] = _json_loads(item.get("evidence"), {})
            item["sources"] = _json_loads(item.get("sources"), [])
            item["is_low_confidence"] = bool(item.get("is_low_confidence"))
            item["is_heuristic"] = bool(item.get("is_heuristic"))
            results.append(item)
        return results
    except Exception:
        logger.warning("Failed to read findings for scan {}", scan_id, exc_info=True)
        return []


def mark_scan_cancelled(scan_id: str, reason: str, owner_id: Optional[str] = None) -> bool:
    try:
        with get_connection() as conn:
            if owner_id:
                cursor = conn.execute(
                    """
                    UPDATE scans
                    SET status = 'cancelled',
                        error_message = ?,
                        completed_at = ?,
                        updated_at = ?
                    WHERE scan_id = ? AND owner_id = ?
                    """,
                    (reason, _utc_now_iso(), _utc_now_iso(), scan_id, owner_id),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE scans
                    SET status = 'cancelled',
                        error_message = ?,
                        completed_at = ?,
                        updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (reason, _utc_now_iso(), _utc_now_iso(), scan_id),
                )
            conn.commit()
            return cursor.rowcount > 0
    except Exception:
        logger.warning("Failed to mark scan {} as cancelled", scan_id, exc_info=True)
        return False


def save_verification_token(domain: str, token: str, expires_at: datetime) -> None:
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO verification_tokens (
                    id, domain, token, status, method_used,
                    created_at, updated_at, expires_at
                ) VALUES (?, ?, ?, 'pending', NULL, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    domain.lower().strip(),
                    token,
                    _utc_now_iso(),
                    _utc_now_iso(),
                    _to_iso(expires_at),
                ),
            )
            conn.commit()
    except Exception:
        logger.warning("Failed to save verification token for {}", domain, exc_info=True)


def get_verification_token(domain: str, token: str) -> Optional[Dict[str, Any]]:
    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM verification_tokens
                WHERE LOWER(domain) = LOWER(?) AND token = ?
                ORDER BY datetime(created_at) DESC
                LIMIT 1
                """,
                (domain.lower().strip(), token),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        logger.warning("Failed to load verification token for {}", domain, exc_info=True)
        return None


def mark_verification_success(domain: str, token: str, method_used: str) -> None:
    try:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE verification_tokens
                SET status = 'verified',
                    method_used = ?,
                    verified_at = ?,
                    updated_at = ?,
                    last_error = NULL
                WHERE LOWER(domain) = LOWER(?) AND token = ?
                """,
                (method_used, _utc_now_iso(), _utc_now_iso(), domain.lower().strip(), token),
            )
            conn.commit()
    except Exception:
        logger.warning("Failed to mark verification success for {}", domain, exc_info=True)


def mark_verification_failure(domain: str, token: str, error_text: str) -> None:
    try:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE verification_tokens
                SET updated_at = ?,
                    last_error = ?
                WHERE LOWER(domain) = LOWER(?) AND token = ?
                """,
                (_utc_now_iso(), error_text[:2000], domain.lower().strip(), token),
            )
            conn.commit()
    except Exception:
        logger.warning("Failed to mark verification failure for {}", domain, exc_info=True)


def get_latest_verification_status(domain: str) -> Optional[Dict[str, Any]]:
    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM verification_tokens
                WHERE LOWER(domain) = LOWER(?)
                ORDER BY datetime(created_at) DESC
                LIMIT 1
                """,
                (domain.lower().strip(),),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        logger.warning("Failed to load latest verification status for {}", domain, exc_info=True)
        return None
