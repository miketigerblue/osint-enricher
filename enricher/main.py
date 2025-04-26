# enricher/main.py

import time
import logging

from sqlalchemy import select
from database import SessionLocal, init_db, ArchiveEntry, AnalysisEntry
from analysis_utils import analyse_entries_batch
from config import settings

def run_loop():
    """
    1) Initialise DB schema
    2) Every `settings.enrich_interval` seconds:
       - Query for unanalysed entries
       - Batch-analyse with progress bar
       - Sleep
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    logger = logging.getLogger(__name__)

    init_db()
    logger.info("Database initialised")

    session = SessionLocal()

    while True:
        subq = select(AnalysisEntry.guid)
        entries = session.query(ArchiveEntry)\
                         .filter(~ArchiveEntry.guid.in_(subq))\
                         .all()
        count = len(entries)
        if count:
            logger.info(f"Found {count} entries to analyse")
            analyse_entries_batch(entries)
            logger.info("Batch analysis complete")
        else:
            logger.info("No new entries to analyse")

        logger.info(f"Sleeping for {settings.enrich_interval} seconds")
        time.sleep(settings.enrich_interval)


if __name__ == "__main__":
    run_loop()
