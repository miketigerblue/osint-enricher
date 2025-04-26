# enricher/database.py

from datetime import datetime
import logging

from sqlalchemy import create_engine, Column, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import settings

logger = logging.getLogger(__name__)

# Engine & Session
engine = create_engine(settings.database_url, echo=False)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class ArchiveEntry(Base):
    __tablename__ = "archive"
    guid      = Column(Text, primary_key=True, index=True)
    title     = Column(Text, nullable=False)
    link      = Column(Text, nullable=False)
    published = Column(DateTime, nullable=True)
    content   = Column(Text, nullable=True)

class AnalysisEntry(Base):
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

def init_db():
    """
    Create tables if they don’t exist.
    """
    logger.info("Creating database tables if needed")
    Base.metadata.create_all(bind=engine)
    logger.info("Database ready")
