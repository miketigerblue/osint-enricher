# enricher/main.py
import time, logging
from database import SessionLocal, init_db, ArchiveEntry, AnalysisEntry
from analysis_utils import analyse_and_persist
from config import settings
from sqlalchemy import exists, select

def run_loop():
    init_db()
    sess = SessionLocal()
    while True:
        # find all archive entries without an analysis row
        subq = select(AnalysisEntry.guid)
        q = sess.query(ArchiveEntry).filter(~ArchiveEntry.guid.in_(subq))
        for entry in q.all():
            try:
                logging.info(f"Analysing {entry.guid}")
                analyse_and_persist(entry)
            except Exception as e:
                logging.exception(f"Failed to analyse {entry.guid}: {e}")
        logging.info(f"Sleeping for {settings.enrich_interval}s")
        time.sleep(settings.enrich_interval)

if __name__ == "__main__":
    run_loop()
