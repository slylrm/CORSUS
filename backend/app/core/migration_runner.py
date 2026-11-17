"""
Database Migration Script
SQLite schema updates for false positive control, WAF detection, cross-validation
"""

import sqlite3
from pathlib import Path
from app.config import settings
from app.utils.logger import logger


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _resolve_db_path() -> str:
    raw_path = settings.DATABASE_URL.split("///")[-1]
    path = Path(raw_path)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


def _add_column_if_missing(cursor: sqlite3.Cursor, table: str, column_definition: str) -> None:
    column_name = column_definition.split()[0]
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_definition}")
        logger.info(f"Added {column_name} column to {table}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            logger.debug(f"{column_name} column already exists in {table}")
        else:
            raise


def apply_migrations():
    """Apply all pending database schema updates"""

    db_path = _resolve_db_path()
    
    logger.info(f"Applying migrations to: {db_path}")

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # ✅ Enable WAL mode for SQLite
        logger.info("Enabling WAL mode...")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        cursor.execute("PRAGMA foreign_keys=ON")

        # ✅ Create scans table with lifecycle-centric schema
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                owner_id TEXT,
                target_url TEXT NOT NULL,
                scan_type TEXT,
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                current_phase TEXT,
                current_tool TEXT,
                tools_json TEXT DEFAULT '[]',
                findings_count INTEGER DEFAULT 0,
                findings_verified INTEGER DEFAULT 0,
                findings_needs_review INTEGER DEFAULT 0,
                correlated_risks_json TEXT DEFAULT '[]',
                report_summary_json TEXT DEFAULT '{}',
                authorization_acknowledged BOOLEAN DEFAULT 0,
                scope_statement TEXT,
                error_message TEXT,
                error_type TEXT,
                error_tool TEXT,
                error_stage TEXT,
                technical_reason TEXT,
                error_hint TEXT,
                waf_detected BOOLEAN DEFAULT 0,
                waf_vendor TEXT,
                waf_confidence_score REAL DEFAULT 0.0,
                rate_limit_detected BOOLEAN DEFAULT 0,
                bot_protection_detected BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP
            )
        """)
        logger.info("Ensured scans table exists")

        scan_columns = [
            "owner_id TEXT",
            "current_phase TEXT",
            "current_tool TEXT",
            "tools_json TEXT DEFAULT '[]'",
            "findings_count INTEGER DEFAULT 0",
            "findings_verified INTEGER DEFAULT 0",
            "findings_needs_review INTEGER DEFAULT 0",
            "correlated_risks_json TEXT DEFAULT '[]'",
            "report_summary_json TEXT DEFAULT '{}'",
            "authorization_acknowledged BOOLEAN DEFAULT 0",
            "scope_statement TEXT",
            "error_message TEXT",
            "error_type TEXT",
            "error_tool TEXT",
            "error_stage TEXT",
            "technical_reason TEXT",
            "error_hint TEXT",
            "waf_detected BOOLEAN DEFAULT 0",
            "waf_vendor TEXT",
            "waf_confidence_score REAL DEFAULT 0.0",
            "rate_limit_detected BOOLEAN DEFAULT 0",
            "bot_protection_detected BOOLEAN DEFAULT 0",
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "started_at TIMESTAMP",
            "completed_at TIMESTAMP",
        ]
        for column_def in scan_columns:
            _add_column_if_missing(cursor, "scans", column_def)

        # ✅ Create findings table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                risk_level TEXT,
                affected_url TEXT,
                tool_name TEXT,
                evidence TEXT,
                recommendation TEXT,
                cwe_id TEXT,
                cvss_score REAL,
                confidence_score REAL DEFAULT 1.0,
                verification_status TEXT DEFAULT 'unverified',
                sources TEXT DEFAULT '[]',
                detection_method TEXT DEFAULT 'automated',
                low_confidence_reason TEXT,
                is_low_confidence BOOLEAN DEFAULT 0,
                is_heuristic BOOLEAN DEFAULT 0,
                found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
            )
        """)
        logger.info("Ensured findings table exists")

        finding_columns = [
            "confidence_score REAL DEFAULT 1.0",
            "verification_status TEXT DEFAULT 'unverified'",
            "sources TEXT DEFAULT '[]'",
            "detection_method TEXT DEFAULT 'automated'",
            "low_confidence_reason TEXT",
            "is_low_confidence BOOLEAN DEFAULT 0",
            "is_heuristic BOOLEAN DEFAULT 0",
            "found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        ]
        for column_def in finding_columns:
            _add_column_if_missing(cursor, "findings", column_def)

        # ✅ Create tool_executions table for logging
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_executions (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT,
                status TEXT DEFAULT 'failed',
                exit_code INTEGER,
                execution_time_seconds REAL,
                stdout TEXT,
                stderr TEXT,
                findings_count INTEGER DEFAULT 0,
                error_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        logger.info("Created/verified tool_executions table")

        tool_execution_columns = [
            "status TEXT DEFAULT 'failed'",
            "findings_count INTEGER DEFAULT 0",
            "error_message TEXT",
        ]
        for column_def in tool_execution_columns:
            _add_column_if_missing(cursor, "tool_executions", column_def)

        # ✅ Domain verification token lifecycle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS verification_tokens (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                token TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                method_used TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                verified_at TIMESTAMP,
                last_error TEXT
            )
        """)
        logger.info("Created/verified verification_tokens table")
        
        # ✅ Create indexes for performance
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_executions_scan_id ON tool_executions(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_executions_tool_name ON tool_executions(tool_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_verification_status ON findings(verification_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_confidence_score ON findings(confidence_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_verification_domain ON verification_tokens(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_verification_token ON verification_tokens(token)")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_verification_domain_token ON verification_tokens(domain, token)")
            logger.info("Created database indexes")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")
        
        # Commit changes
        conn.commit()
        logger.info("✅ All migrations applied successfully")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        raise
    
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    apply_migrations()
