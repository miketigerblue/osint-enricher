"""
Database setup and ORM models for the OSINT Enricher service.

This module defines:
- SQLAlchemy engine and session factory
- Declarative Base for ORM
- ArchiveEntry: stores raw feed items as produced by the Rust ingestor
- CurrentEntry: stores current feed items
- AnalysisEntry: stores enriched threat-intel results, including advanced fields and feed/source metadata
- init_db(): helper to create all tables on startup
"""

from datetime import datetime
from sqlalchemy import (
    create_engine,
    Column,
    Text,
    DateTime,
    JSON,
    ARRAY
)
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

# ──────────────────────────────────────────────────────────────
# 1. Engine & Session Setup
# ──────────────────────────────────────────────────────────────

# Create SQLAlchemy engine using the database URL from config
engine = create_engine(settings.database_url, echo=False)

# Session factory for transactional DB access
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Declarative base for ORM models
Base = declarative_base()

# ──────────────────────────────────────────────────────────────
# 2. ORM Models
# ──────────────────────────────────────────────────────────────

class ArchiveEntry(Base):
    """
    Mirrors the 'archive' table created by the Rust ingestor.

    Columns: guid (PK), title, link, published, content, summary, author,
    categories, entry_updated, feed_url, feed_title, feed_description,
    feed_language, feed_icon, feed_updated
    """
    __tablename__ = "archive"
    guid = Column(Text, primary_key=True, index=True)
    title = Column(Text, nullable=False)
    link = Column(Text, nullable=False)
    published = Column(DateTime, nullable=True)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    author = Column(Text, nullable=True)
    categories = Column(ARRAY(Text), nullable=True)
    entry_updated = Column(DateTime, nullable=True)
    # Feed/source metadata
    feed_url = Column(Text, nullable=False)
    feed_title = Column(Text, nullable=True)
    feed_description = Column(Text, nullable=True)
    feed_language = Column(Text, nullable=True)
    feed_icon = Column(Text, nullable=True)
    feed_updated = Column(DateTime, nullable=True)

class CurrentEntry(Base):
    """
    Mirrors the 'current' table (same schema as archive).
    """
    __tablename__ = "current"
    guid = Column(Text, primary_key=True, index=True)
    title = Column(Text, nullable=False)
    link = Column(Text, nullable=False)
    published = Column(DateTime, nullable=True)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    author = Column(Text, nullable=True)
    categories = Column(ARRAY(Text), nullable=True)
    entry_updated = Column(DateTime, nullable=True)
    # Feed/source metadata
    feed_url = Column(Text, nullable=False)
    feed_title = Column(Text, nullable=True)
    feed_description = Column(Text, nullable=True)
    feed_language = Column(Text, nullable=True)
    feed_icon = Column(Text, nullable=True)
    feed_updated = Column(DateTime, nullable=True)

class AnalysisEntry(Base):
    """
    Stores the structured threat analysis produced by the LLM.
    Includes advanced threat intelligence fields and feed/source metadata.
    """
    __tablename__ = "analysis"
    guid = Column(Text, primary_key=True, index=True)
    # Core analysis fields
    severity_level = Column(Text, nullable=True)
    confidence = Column(Text, nullable=True)
    recommended_actions = Column(JSON, nullable=True)
    key_IOCs = Column(JSON, nullable=True)
    affected_systems_sectors = Column(JSON, nullable=True)
    mitigation_strategies = Column(JSON, nullable=True)
    potential_threat_actors = Column(JSON, nullable=True)
    historical_context = Column(Text, nullable=True)
    summary_impact = Column(Text, nullable=True)
    relevance = Column(Text, nullable=True)
    additional_notes = Column(Text, nullable=True)
    cve_references = Column(JSON, nullable=True)
    # Advanced threat fields
    ttps = Column(JSON, nullable=True)
    attack_vectors = Column(JSON, nullable=True)
    tools_used = Column(JSON, nullable=True)
    malware_families = Column(JSON, nullable=True)
    target_geographies = Column(JSON, nullable=True)
    exploit_references = Column(JSON, nullable=True)
    # Source metadata (feed-level)
    source_name = Column(Text, nullable=True)        # Typically the feed title
    source_url = Column(Text, nullable=True)         # Typically the feed URL
    feed_title = Column(Text, nullable=True)
    feed_description = Column(Text, nullable=True)
    feed_language = Column(Text, nullable=True)
    feed_icon = Column(Text, nullable=True)
    feed_updated = Column(DateTime, nullable=True)
    # Timestamp of analysis
    analysed_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        doc="UTC timestamp when analysis was performed"
    )

# ──────────────────────────────────────────────────────────────
# 3. Database Initialisation
# ──────────────────────────────────────────────────────────────

def init_db():
    """
    Create all tables in the database if they do not exist.
    Call this on service startup.
    """
    Base.metadata.create_all(bind=engine)