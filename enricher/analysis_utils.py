"""
analysis_utils.py

Analysis utility module for the OSINT Enricher service, with optional Rich progress bars and status spinners.

Responsibilities:
  1) Load and configure the OpenAI LLM client
  2) Define a strict JSON schema in the prompt
  3) Build a ChatPromptTemplate → LLM → JsonOutputParser chain
  4) Provide analyse_and_persist() to:
       a) Format prompt inputs
       b) Invoke the chain
       c) Persist AnalysisEntry in Postgres
       d) Store an embedding in ChromaDB
  5) Provide analyse_entries_batch() to run a batch with a progress bar
"""

import uuid
import os
from datetime import datetime

from dotenv import load_dotenv

# Rich for console progress bars
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

# LangChain LLM and parser
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

# Local modules
from database import SessionLocal, AnalysisEntry
from chromadb_utils import store_analysis_vector
from config import settings

# ────────────────────────────────────────────────────────────────────────────────
# 0) Initialise
# ────────────────────────────────────────────────────────────────────────────────
load_dotenv()

_console = Console(force_terminal=True)

llm = ChatOpenAI(
    model_name="gpt-4o",
    temperature=0.0,
    max_retries=5,
    request_timeout=60
)

SCHEMA = """
{{  
  "severity_level":           "string (e.g. LOW, MEDIUM, HIGH, CRITICAL)",  
  "confidence":               "string (e.g. 87%)",  
  "recommended_actions":      ["array", "of", "strings"],  
  "key_IOCs":                 ["array", "of", "strings"],  
  "affected_systems_sectors": ["array", "of", "strings"],  
  "mitigation_strategies":    ["array", "of", "strings"],  
  "potential_threat_actors":  ["array", "of", "strings"],  
  "historical_context":       "string",  
  "summary_impact":           "string",  
  "relevance":                "string",  
  "additional_notes":         "string",  
  "cve_references":           ["array", "of", "CVE identifiers"]  
}}
"""

PROMPT = f"""
You are a cybersecurity analyst. Analyse the article and respond strictly in JSON, matching this schema:
{SCHEMA}

Title: {{title}}
Link: {{link}}
Published: {{published}}
Content: {{content}}

IMPORTANT: Reply *only* with the JSON object—no extra explanation.
"""

prompt = ChatPromptTemplate.from_template(PROMPT)
parser = JsonOutputParser()
analysis_chain = prompt | llm | parser


def analyse_and_persist(entry):
    """
    Analyze a single ArchiveEntry and persist results to Postgres + ChromaDB.
    """
    inputs = {
        "title":     entry.title or "",
        "link":      entry.link  or "",
        "published": entry.published.isoformat() if entry.published else "",
        "content":   entry.content or "",
    }
    result: dict = analysis_chain.invoke(inputs)

    # Persist to Postgres
    session = SessionLocal()
    analysis = AnalysisEntry(
        guid                     = entry.guid,
        severity_level           = result.get("severity_level"),
        confidence               = result.get("confidence"),
        recommended_actions      = result.get("recommended_actions"),
        key_IOCs                 = result.get("key_IOCs"),
        affected_systems_sectors = result.get("affected_systems_sectors"),
        mitigation_strategies    = result.get("mitigation_strategies"),
        potential_threat_actors  = result.get("potential_threat_actors"),
        historical_context       = result.get("historical_context"),
        summary_impact           = result.get("summary_impact"),
        relevance                = result.get("relevance"),
        additional_notes         = result.get("additional_notes"),
        cve_references           = result.get("cve_references"),
        source_name              = entry.link,
        source_url               = entry.link,
        analysed_at              = datetime.utcnow()
    )
    session.add(analysis)
    session.commit()
    session.close()

    # Store in ChromaDB
    store_analysis_vector(
        document_id    = entry.guid,
        analysis_result= result,
        title          = entry.title,
        url            = entry.link
    )


def analyse_entries_batch(entries):
    """
    Analyse and persist a batch of entries with a console progress bar.

    Uses SHOW_PROGRESS (bool) from settings to toggle the bar.
    """
    show = settings.show_progress
    if show:
        total = len(entries)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=_console
        ) as progress:
            task = progress.add_task("Analysing entries", total=total)
            for entry in entries:
                analyse_and_persist(entry)
                progress.advance(task)
    else:
        for entry in entries:
            analyse_and_persist(entry)
