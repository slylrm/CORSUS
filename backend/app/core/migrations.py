"""
Database Schema Updates
False positive kontrolü, WAF detection, cross-validation için gerekli alanlar
"""

# SQLAlchemy migration örneği
# Mevcut findings table'a yeni alanlar ekle

"""
ALTER TABLE findings ADD COLUMN confidence_score REAL DEFAULT 1.0;
ALTER TABLE findings ADD COLUMN verification_status TEXT DEFAULT 'unverified';
ALTER TABLE findings ADD COLUMN sources TEXT; -- JSON array
ALTER TABLE findings ADD COLUMN detection_method TEXT DEFAULT 'automated';
ALTER TABLE findings ADD COLUMN low_confidence_reason TEXT;
ALTER TABLE findings ADD COLUMN is_low_confidence BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN is_heuristic BOOLEAN DEFAULT FALSE;

-- WAF Detection
ALTER TABLE scans ADD COLUMN waf_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scans ADD COLUMN waf_vendor TEXT;
ALTER TABLE scans ADD COLUMN waf_confidence_score REAL DEFAULT 0.0;
ALTER TABLE scans ADD COLUMN rate_limit_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE scans ADD COLUMN bot_protection_detected BOOLEAN DEFAULT FALSE;

-- Phase tracking
ALTER TABLE scans ADD COLUMN phase_progress TEXT; -- JSON
ALTER TABLE scans ADD COLUMN current_phase TEXT;

-- Tool execution logs
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
);

CREATE INDEX idx_tool_executions_scan_id ON tool_executions(scan_id);
CREATE INDEX idx_tool_executions_tool_name ON tool_executions(tool_name);
"""

# SQLite WAL mode enable
"""
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=30000;  -- 30 seconds
"""
