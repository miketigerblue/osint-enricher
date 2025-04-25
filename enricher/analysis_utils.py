# enricher/analysis_utils.py

"""
Analysis utility module for the OSINT Enricher service.

Responsibilities:
  1) Load and configure the OpenAI LLM client
  2) Define a strict JSON schema in the prompt (escaped so LangChain
     doesn’t mistake JSON braces for template variables)
  3) Build a ChatPromptTemplate → LLM → JsonOutputParser chain
  4) Provide analyse_and_persist() to:
       a) Format the prompt inputs
       b) Invoke the chain
       c) Persist AnalysisEntry in Postgres
       d) Store an embedding in ChromaDB
"""

import uuid
import os
from datetime import datetime

from dotenv import load_dotenv

# ChatOpenAI client (from langchain-openai package)
from langchain_openai import ChatOpenAI

# For defining/filling our prompt template
from langchain.prompts import ChatPromptTemplate

# To force the model output to valid JSON
from langchain_core.output_parsers import JsonOutputParser

from database import SessionLocal, AnalysisEntry
from chromadb_utils import store_analysis_vector

# ─────────────────────────────────────────────────────────────────────────────
# ENV: Load .env (OPENAI_API_KEY, DATABASE_URL, etc.)
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# 1) Initialise the ChatOpenAI LLM
# ─────────────────────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model_name="gpt-4o",    # or your preferred model
    temperature=0.0,        # deterministic output
    max_retries=5,
    request_timeout=60
)

# ─────────────────────────────────────────────────────────────────────────────
# 2) Build a JSON schema literal (double {{ and }} to escape actual braces)
# ─────────────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────────────
# 3) Compose the prompt template (only these four placeholders!)
# ─────────────────────────────────────────────────────────────────────────────
PROMPT = f"""
You are a cybersecurity analyst. Analyse the article and respond strictly in JSON, matching this schema:
{SCHEMA}

Title: {{title}}
Link: {{link}}
Published: {{published}}
Content: {{content}}

IMPORTANT: Reply *only* with the JSON object—no extra explanation.
"""

# Build the LangChain chain: prompt → LLM → JSON parser
prompt = ChatPromptTemplate.from_template(PROMPT)
parser = JsonOutputParser()
analysis_chain = prompt | llm | parser

# ─────────────────────────────────────────────────────────────────────────────
# 4) Main analysis function
# ─────────────────────────────────────────────────────────────────────────────
def analyse_and_persist(entry):
    """
    entry: ArchiveEntry ORM instance
      - guid, title, link, published (datetime), content (string)

    Workflow:
      1) Prepare only the four keys we reference in the template
      2) Invoke the chain (LLM → JSON)
      3) Persist AnalysisEntry to Postgres
      4) Generate & store embedding in ChromaDB
    """

    # 1) Build inputs dict for our four template variables
    inputs = {
        "title":     entry.title or "",
        "link":      entry.link  or "",
        # convert datetime to ISO string
        "published": entry.published.isoformat() if entry.published else "",
        "content":   entry.content or "",
    }

    # 2) Run the LLM chain and parse to a Python dict
    result: dict = analysis_chain.invoke(inputs)

    # 3) Write the parsed analysis to Postgres
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

    # 4) Store embedding + metadata in ChromaDB
    #    NOTE: store_analysis_vector signature is:
    #       def store_analysis_vector(doc_id, analysis_dict, title, url)
    vector_id = str(uuid.uuid4())
    store_analysis_vector(
        vector_id,      # unique ID for this embedding
        result,         # the full analysis dict from the LLM
        entry.title,    # article title
        entry.link      # article URL
    )

    session.close()
