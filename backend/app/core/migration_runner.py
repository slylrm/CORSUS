"""
Database Migration Script
SQLite schema updates for false positive control, WAF detection, cross-validation
"""

import sqlite3
from pathlib import Path
from app.config import settings
from app.utils.logger import logger


def apply_migrations():
    """Apply all pending database schema updates"""
    
    # Extract database path from DATABASE_URL
    # sqlite+aiosqlite:///./weppentest.db -> ./weppentest.db
    db_path = settings.DATABASE_URL.split("///")[-1]
    
    logger.info(f"Applying migrations to: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # ✅ Enable WAL mode for SQLite
        logger.info("Enabling WAL mode...")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
        cursor.execute("PRAGMA foreign_keys=ON")
        
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
        
        # ✅ Add confidence_score column to findings
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN confidence_score REAL DEFAULT 1.0")
            logger.info("Added confidence_score column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("confidence_score column already exists")
            else:
                raise
        
        # ✅ Add verification_status column
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN verification_status TEXT DEFAULT 'unverified'")
            logger.info("Added verification_status column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("verification_status column already exists")
            else:
                raise
        
        # ✅ Add sources column (JSON array)
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN sources TEXT DEFAULT '[]'")
            logger.info("Added sources column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("sources column already exists")
            else:
                raise
        
        # ✅ Add detection_method column
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN detection_method TEXT DEFAULT 'automated'")
            logger.info("Added detection_method column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("detection_method column already exists")
            else:
                raise
        
        # ✅ Add low_confidence_reason column
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN low_confidence_reason TEXT")
            logger.info("Added low_confidence_reason column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("low_confidence_reason column already exists")
            else:
                raise
        
        # ✅ Add flag columns for UI hints
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN is_low_confidence BOOLEAN DEFAULT 0")
            logger.info("Added is_low_confidence column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("is_low_confidence column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE findings ADD COLUMN is_heuristic BOOLEAN DEFAULT 0")
            logger.info("Added is_heuristic column")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("is_heuristic column already exists")
            else:
                raise
        
        # ✅ WAF Detection columns in scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                scan_type TEXT,
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                current_phase TEXT DEFAULT 'Asset Discovery',
                current_tool TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                waf_detected BOOLEAN DEFAULT 0,
                waf_vendor TEXT,
                rate_limit_detected BOOLEAN DEFAULT 0,
                bot_protection_detected BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        logger.info("Ensured scans table exists")
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN waf_detected BOOLEAN DEFAULT 0")
            logger.info("Added waf_detected column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("waf_detected column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN waf_vendor TEXT")
            logger.info("Added waf_vendor column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("waf_vendor column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN waf_confidence_score REAL DEFAULT 0.0")
            logger.info("Added waf_confidence_score column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("waf_confidence_score column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN rate_limit_detected BOOLEAN DEFAULT 0")
            logger.info("Added rate_limit_detected column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("rate_limit_detected column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN bot_protection_detected BOOLEAN DEFAULT 0")
            logger.info("Added bot_protection_detected column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("bot_protection_detected column already exists")
            else:
                raise
        
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN current_phase TEXT DEFAULT 'discovery'")
            logger.info("Added current_phase column to scans")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                logger.debug("current_phase column already exists")
            else:
                raise
        
        # ✅ Create tool_executions table for logging
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tool_executions (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT,
                exit_code INTEGER,
                execution_time_seconds REAL,
                stdout TEXT,
                stderr TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        logger.info("Created/verified tool_executions table")
        
        # ✅ Create indexes for performance
        try:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_executions_scan_id ON tool_executions(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_executions_tool_name ON tool_executions(tool_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_verification_status ON findings(verification_status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_confidence_score ON findings(confidence_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
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
        conn.close()


if __name__ == "__main__":
    apply_migrations()
