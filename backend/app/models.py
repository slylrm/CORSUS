"""
SQLAlchemy ORM Models
Database table definitions
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any
from contextlib import contextmanager

from sqlalchemy import Column, String, Text, Float, Boolean, DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from app.config import settings
from app.utils.logger import logger

Base = declarative_base()

# Database engine and session factory
_engine = None
_SessionLocal = None


def get_engine():
    """Get or create SQLAlchemy engine"""
    global _engine
    if _engine is None:
        # Convert async URL to sync URL for SQLAlchemy
        db_url = settings.DATABASE_URL.replace("sqlite+aiosqlite://", "sqlite://")
        _engine = create_engine(db_url, connect_args={"check_same_thread": False})
    return _engine


def get_session():
    """Create a new database session"""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autocommit=False, autoflush=False)
    return _SessionLocal()


@contextmanager
def get_db_session():
    """Context manager for database sessions - ensures proper cleanup"""
    session = None
    try:
        session = get_session()
        yield session
    finally:
        if session:
            session.close()



class Finding(Base):
    """
    Security finding model
    Represents a vulnerability or security issue discovered during scanning
    """
    __tablename__ = "findings"
    
    # Primary key
    id = Column(String, primary_key=True, nullable=False)
    
    # Foreign key
    scan_id = Column(String, ForeignKey("scans.scan_id"), nullable=False, index=True)
    
    # Basic information
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    risk_level = Column(String, nullable=True)
    affected_url = Column(String, nullable=True)
    tool_name = Column(String, nullable=True)
    
    # Technical details
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    cwe_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    
    # Validation and confidence fields
    confidence_score = Column(Float, default=1.0, nullable=True)
    verification_status = Column(String, default="unverified", nullable=True)
    sources = Column(Text, default="[]", nullable=True)  # JSON array stored as text
    detection_method = Column(String, default="automated", nullable=True)
    low_confidence_reason = Column(Text, nullable=True)
    is_low_confidence = Column(Boolean, default=False, nullable=True)
    is_heuristic = Column(Boolean, default=False, nullable=True)
    
    # Timestamp
    found_at = Column(DateTime, default=func.now(), nullable=True)
    
    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, risk_level={self.risk_level})>"


def insert_fingerprint_findings(scan_id: str, tool_result, target_url: str = None) -> int:
    """
    Insert fingerprint findings into database
    
    Args:
        scan_id: Scan identifier
        tool_result: ToolResult object with findings list
        target_url: Optional target URL for validation fallback
        
    Returns:
        Number of findings inserted
    """
    inserted_count = 0
    
    with get_db_session() as session:
        try:
            # Get findings from tool_result
            findings_list = tool_result.findings if hasattr(tool_result, 'findings') else []
            
            if not findings_list:
                logger.info(f"[FINGERPRINT][DB] No findings to insert for scan_id={scan_id}")
                return 0
            
            # Extract target_url from tool_result if not provided
            if not target_url and hasattr(tool_result, 'target'):
                target_url = tool_result.target
            
            # Prepare bulk insert mappings
            mappings = []
            for finding_dict in findings_list:
                # Generate unique ID if not present
                finding_id = finding_dict.get('id') or f"finding-{uuid.uuid4()}"
            
                # Safe JSON serialization for evidence
                try:
                    evidence_value = finding_dict.get('evidence', {})
                    if isinstance(evidence_value, dict):
                        evidence_json = json.dumps(evidence_value)
                    else:
                        evidence_json = str(evidence_value)
                except (TypeError, ValueError) as e:
                    logger.warning(f"[FINGERPRINT][DB] JSON serialization failed for evidence in finding {finding_id}: {e}")
                    evidence_json = "{}"
            
                # Safe JSON serialization for sources
                try:
                    sources_json = json.dumps(finding_dict.get('sources', []))
                except (TypeError, ValueError) as e:
                    logger.warning(f"[FINGERPRINT][DB] JSON serialization failed for sources in finding {finding_id}: {e}")
                    sources_json = "[]"
            
                # Validate title (None or empty -> "Unknown")
                title = finding_dict.get('title')
                if not title or (isinstance(title, str) and not title.strip()):
                    title = 'Unknown'
            
                # Validate risk_level (must be valid level)
                risk_level = finding_dict.get('risk_level', 'info')
                valid_risk_levels = ['critical', 'high', 'medium', 'low', 'info']
                if risk_level not in valid_risk_levels:
                    risk_level = 'info'
            
                # Validate confidence_score (None -> 0.0)
                confidence_score = finding_dict.get('confidence_score')
                if confidence_score is None:
                    confidence_score = 0.0
            
                # Validate affected_url (None -> target_url)
                affected_url = finding_dict.get('affected_url')
                if not affected_url:
                    affected_url = target_url
            
                # Prepare mapping dict
                mapping = {
                    'id': finding_id,
                    'scan_id': scan_id,
                    'title': title,
                    'description': finding_dict.get('description'),
                    'risk_level': risk_level,
                    'affected_url': affected_url,
                    'tool_name': finding_dict.get('tool_name', 'fingerprint'),
                    'evidence': evidence_json,
                    'recommendation': finding_dict.get('recommendation'),
                    'cwe_id': finding_dict.get('cwe_id'),
                    'cvss_score': finding_dict.get('cvss_score'),
                    'confidence_score': confidence_score,
                    'verification_status': finding_dict.get('verification_status', 'unverified'),
                    'sources': sources_json,
                    'detection_method': finding_dict.get('detection_method', 'automated'),
                    'low_confidence_reason': finding_dict.get('low_confidence_reason'),
                    'is_low_confidence': finding_dict.get('is_low_confidence', False),
                    'is_heuristic': finding_dict.get('is_heuristic', False),
                    'found_at': datetime.utcnow()
                }
                mappings.append(mapping)
        
            # Bulk insert all findings in one operation
            session.bulk_insert_mappings(Finding, mappings)
            inserted_count = len(mappings)
            
            # Commit all findings
            session.commit()
            logger.info(f"[FINGERPRINT][DB] Inserted {inserted_count} findings scan_id={scan_id}")
            
            return inserted_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"[FINGERPRINT][DB] Error inserting findings: {e}", exc_info=True)
            raise



def read_fingerprint_findings(scan_id: str) -> List[Finding]:
    """
    Read fingerprint findings from database
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        List of Finding objects (max 5, ordered by found_at DESC)
        Returns empty list on error
    """
    with get_db_session() as session:
        try:
            # Query findings with filters
            findings = session.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.tool_name == 'fingerprint'
            ).order_by(
                Finding.found_at.desc()
            ).limit(5).all()
            
            # Log results
            logger.info(f"[FINGERPRINT][DB] Read {len(findings)} findings for scan_id={scan_id}")
            
            for idx, finding in enumerate(findings, 1):
                logger.debug(f"  {idx}. {finding.title} | {finding.risk_level} | {finding.found_at}")
            
            return findings
            
        except Exception as e:
            logger.error(f"[FINGERPRINT][DB] Error reading findings for scan_id={scan_id}: {e}", exc_info=True)
            return []


def insert_whatweb_findings(scan_id: str, tool_result, target_url: str = None) -> int:
    """
    Insert WhatWeb findings into database
    
    Args:
        scan_id: Scan identifier
        tool_result: ToolResult object with findings list
        target_url: Optional target URL for validation fallback
        
    Returns:
        Number of findings inserted
    """
    inserted_count = 0
    
    with get_db_session() as session:
        try:
            # Get findings from tool_result
            findings_list = tool_result.findings if hasattr(tool_result, 'findings') else []
            
            if not findings_list:
                logger.info(f"[WHATWEB][DB] No findings to insert for scan_id={scan_id}")
                return 0
            
            # Extract target_url from tool_result if not provided
            if not target_url and hasattr(tool_result, 'target'):
                target_url = tool_result.target
            
            # Prepare bulk insert mappings
            mappings = []
            for finding_dict in findings_list:
                # Generate unique ID if not present
                finding_id = finding_dict.get('id') or f"finding-{uuid.uuid4()}"
                
                # Safe JSON serialization for evidence
                try:
                    evidence_value = finding_dict.get('evidence', {})
                    if isinstance(evidence_value, dict):
                        evidence_json = json.dumps(evidence_value)
                    else:
                        evidence_json = str(evidence_value)
                except (TypeError, ValueError) as e:
                    logger.warning(f"[WHATWEB][DB] JSON serialization failed for evidence in finding {finding_id}: {e}")
                    evidence_json = "{}"
                
                # Safe JSON serialization for sources
                try:
                    sources_json = json.dumps(finding_dict.get('sources', []))
                except (TypeError, ValueError) as e:
                    logger.warning(f"[WHATWEB][DB] JSON serialization failed for sources in finding {finding_id}: {e}")
                    sources_json = "[]"
                
                # Validate title (None or empty → "Unknown")
                title = finding_dict.get('title')
                if not title or (isinstance(title, str) and not title.strip()):
                    title = 'Unknown'
                
                # Validate risk_level (must be valid level)
                risk_level = finding_dict.get('risk_level', 'info')
                valid_risk_levels = ['critical', 'high', 'medium', 'low', 'info']
                if risk_level not in valid_risk_levels:
                    risk_level = 'info'
                
                # Validate confidence_score (None → 0.0)
                confidence_score = finding_dict.get('confidence_score')
                if confidence_score is None:
                    confidence_score = 0.0
                
                # Validate affected_url (None → target_url)
                affected_url = finding_dict.get('affected_url')
                if not affected_url:
                    affected_url = target_url
                
                # Prepare mapping dict
                mapping = {
                    'id': finding_id,
                    'scan_id': scan_id,
                    'title': title,
                    'description': finding_dict.get('description'),
                    'risk_level': risk_level,
                    'affected_url': affected_url,
                    'tool_name': finding_dict.get('tool_name', 'whatweb'),
                    'evidence': evidence_json,
                    'recommendation': finding_dict.get('recommendation'),
                    'cwe_id': finding_dict.get('cwe_id'),
                    'cvss_score': finding_dict.get('cvss_score'),
                    'confidence_score': confidence_score,
                    'verification_status': finding_dict.get('verification_status', 'unverified'),
                    'sources': sources_json,
                    'detection_method': finding_dict.get('detection_method', 'automated'),
                    'low_confidence_reason': finding_dict.get('low_confidence_reason'),
                    'is_low_confidence': finding_dict.get('is_low_confidence', False),
                    'is_heuristic': finding_dict.get('is_heuristic', False),
                    'found_at': datetime.utcnow()
                }
                mappings.append(mapping)
            
            # Bulk insert all findings in one operation
            session.bulk_insert_mappings(Finding, mappings)
            inserted_count = len(mappings)
            
            # Commit all findings
            session.commit()
            logger.info(f"[WHATWEB][DB] Inserted {inserted_count} findings scan_id={scan_id}")
            
            return inserted_count
            
        except Exception as e:
            session.rollback()
            logger.error(f"[WHATWEB][DB] Error inserting findings: {e}", exc_info=True)
            raise


def read_whatweb_findings(scan_id: str) -> List[Finding]:
    """
    Read WhatWeb findings from database
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        List of Finding objects (max 5, ordered by found_at DESC)
        Returns empty list on error
    """
    with get_db_session() as session:
        try:
            # Query findings with filters
            findings = session.query(Finding).filter(
                Finding.scan_id == scan_id,
                Finding.tool_name == 'whatweb'
            ).order_by(
                Finding.found_at.desc()
            ).limit(5).all()
            
            # Log results
            logger.info(f"[WHATWEB][DB] Read {len(findings)} findings for scan_id={scan_id}")
            
            for idx, finding in enumerate(findings, 1):
                logger.debug(f"  {idx}. {finding.title} | {finding.risk_level} | {finding.found_at}")
            
            return findings
            
        except Exception as e:
            logger.error(f"[WHATWEB][DB] Error reading findings for scan_id={scan_id}: {e}", exc_info=True)
            return []


