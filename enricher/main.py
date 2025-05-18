# enricher/main.py

import time
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.logging import RichHandler
from database import SessionLocal, init_db, ArchiveEntry, AnalysisEntry
from analysis_utils import analyse_and_persist
from config import settings
from sqlalchemy import select

# ──────────────────────────────────────────────────────────────
# Configure rich logging with timestamps and pretty tracebacks
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger("osint-enricher")

# Console for rich output (optional, used by progress)
console = Console()

def run_loop():
    """
    Main service loop:
    - Initialize DB
    - Query archive entries missing analysis
    - Analyse each entry with rich progress bar and logging
    - Sleep between cycles
    """
    init_db()
    logger.info("Starting OSINT Enricher service loop.")

    # Create a fresh session each loop iteration to avoid stale connections
    while True:
        session = SessionLocal()
        try:
            # Subquery for GUIDs already analysed
            subq = select(AnalysisEntry.guid)
            # Query archive entries not yet analysed
            q = session.query(ArchiveEntry).filter(~ArchiveEntry.guid.in_(subq))
            entries = q.all()

            if not entries:
                logger.info("No new archive entries to analyse. Sleeping...")
            else:
                logger.info(f"Found {len(entries)} entries to analyse.")

                # Use rich progress bar to visualize analysis progress
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,  # Clear progress bar after completion
                ) as progress:
                    task = progress.add_task("Analysing entries...", total=len(entries))

                    for entry in entries:
                        try:
                            logger.info(f"Starting analysis of GUID: {entry.guid}")
                            analyse_and_persist(entry)
                            logger.info(f"[green]Successfully analysed GUID: {entry.guid}[/green]")
                        except Exception as e:
                            logger.error(f"[red]Failed to analyse GUID: {entry.guid}[/red] - {e}")
                        finally:
                            progress.advance(task)

            logger.info(f"Sleeping for {settings.enrich_interval} seconds before next cycle.")
        except Exception as e:
            logger.error(f"[red]Unexpected error in main loop:[/red] {e}")
        finally:
            session.close()

        time.sleep(settings.enrich_interval)

if __name__ == "__main__":
    run_loop()