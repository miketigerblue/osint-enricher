# enricher/database.py

"""
Database setup and ORM models for the OSINT Enricher service.

Defines:
  - SQLAlchemy engine and session factory
  - Declarative Base
  - ArchiveEntry: stores raw feed items as produced by the Rust ingestor:
      guid, title, link, published, content
  - AnalysisEntry: stores enriched threat-intel results
  - init_db(): helper to create all tables on startup
"""

from datetime import datetime

from sqlalchemy import (
    create_engine,
    Column,
    Text,
    DateTime,
    JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import settings

# ─────────────────────────────────────────────────────────────────────────────
# 1) Engine & Session setup
# ─────────────────────────────────────────────────────────────────────────────

# Use the DATABASE_URL from your .env via Settings
engine = create_engine(settings.database_url, echo=False)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()

# ─────────────────────────────────────────────────────────────────────────────
# 2) ORM Models (match your existing 'archive' schema exactly)
# ─────────────────────────────────────────────────────────────────────────────

class ArchiveEntry(Base):
    """
    Mirrors the 'archive' table created by the Rust ingestor.
    Columns: guid (PK), title, link, published, content.
    """
    __tablename__ = "archive"

    guid      = Column(Text, primary_key=True, index=True)
    title     = Column(Text, nullable=False)
    link      = Column(Text, nullable=False)
    published = Column(DateTime, nullable=True)
    content   = Column(Text, nullable=True)


class AnalysisEntry(Base):
    """
    Stores the structured threat analysis produced by the LLM.
    """
    __tablename__ = "analysis"

    guid                     = Column(Text, primary_key=True, index=True)
    severity_level           = Column(Text, nullable=True)
    confidence               = Column(Text, nullable=True)
    recommended_actions      = Column(JSON, nullable=True)
    key_IOCs                 = Column(JSON, nullable=True)
    affected_systems_sectors = Column(JSON, nullable=True)
    mitigation_strategies    = Column(JSON, nullable=True)
    potential_threat_actors  = Column(JSON, nullable=True)
    historical_context       = Column(Text, nullable=True)
    summary_impact           = Column(Text, nullable=True)
    relevance                = Column(Text, nullable=True)
    additional_notes         = Column(Text, nullable=True)
    cve_references           = Column(JSON, nullable=True)
    source_name              = Column(Text, nullable=True)
    source_url               = Column(Text, nullable=True)
    analysed_at              = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        doc="UTC timestamp when analysis was performed"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3) Database initialisation
# ─────────────────────────────────────────────────────────────────────────────

def init_db():
    """
    Create all tables in the database if they do not exist.
    Call this on service startup.
    """
    Base.metadata.create_all(bind=engine)
