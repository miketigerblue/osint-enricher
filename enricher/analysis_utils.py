"""
Analysis utility module for the OSINT Enricher service.

Responsibilities:
 1. Load and configure the OpenAI LLM client
 2. Define a strict JSON schema in the prompt
 3. Build a ChatPromptTemplate → LLM → JsonOutputParser chain
 4. Provide analyse_and_persist() to:
    a. Format the prompt inputs
    b. Invoke the chain
    c. Persist AnalysisEntry in Postgres
    d. Store an embedding in ChromaDB
 5. RAG: Retrieve similar threat analyses for context
 6. Smart truncation to keep embedding queries within token limits
"""

import uuid
from datetime import datetime
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from database import SessionLocal, AnalysisEntry
from chromadb_utils import store_analysis_vector
from config import settings

from rich.console import Console
from rich.logging import RichHandler
import logging

# Initialize rich console and configure logging for colorful output
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)],
)
logger = logging.getLogger("osint-enricher")

# ──────────────────────────────────────────────────────────────
# 1. Load environment variables (OPENAI_API_KEY, DATABASE_URL, etc.)
# ──────────────────────────────────────────────────────────────
load_dotenv()

# ──────────────────────────────────────────────────────────────
# 2. Initialise the ChatOpenAI LLM
# ──────────────────────────────────────────────────────────────
llm = ChatOpenAI(
    model_name="gpt-4.1-mini",  # Small but mighty model (token limits still apply!)
    temperature=0.0,            # No surprises, just facts please
    max_retries=5,
    request_timeout=60
)

# ──────────────────────────────────────────────────────────────
# 3. Build a JSON schema literal (escaped for template safety)
# ──────────────────────────────────────────────────────────────
SCHEMA = """
{{
 "severity_level": "string (e.g. LOW, MEDIUM, HIGH, CRITICAL)",
 "confidence": "string (e.g. 87%)",
 "recommended_actions": ["array", "of", "strings"],
 "key_IOCs": ["array", "of", "strings"],
 "affected_systems_sectors": ["array", "of", "strings"],
 "mitigation_strategies": ["array", "of", "strings"],
 "potential_threat_actors": ["array", "of", "strings"],
 "historical_context": "string",
 "summary_impact": "string",
 "relevance": "string",
 "additional_notes": "string",
 "cve_references": ["array", "of", "CVE identifiers"],
 "ttps": ["array", "of", "strings, e.g. MITRE ATT&CK tactic/technique names or IDs"],
 "attack_vectors": ["array", "of", "strings, e.g. phishing, RDP brute force, supply chain"],
 "tools_used": ["array", "of", "strings, e.g. Cobalt Strike, Mimikatz"],
 "malware_families": ["array", "of", "strings, e.g. Emotet, TrickBot"],
 "target_geographies": ["array", "of", "strings, e.g. USA, Europe, APAC"],
 "exploit_references": ["array", "of", "URLs or references to exploits, PoCs, or advisories"]
}}
"""

# ──────────────────────────────────────────────────────────────
# 4. Compose the prompt template (with RAG and metadata fields)
# ──────────────────────────────────────────────────────────────
PROMPT = f"""
You are a cybersecurity analyst. Here are similar past threats:
{{retrieved_context}}

Feed Info:
- Feed Title: {{feed_title}}
- Feed Description: {{feed_description}}
- Feed Language: {{feed_language}}
- Feed Icon: {{feed_icon}}
- Feed Updated: {{feed_updated}}

Article Info:
- Title: {{title}}
- Author: {{author}}
- Published: {{published}}
- Updated: {{entry_updated}}
- Link: {{link}}
- Categories: {{categories}}
- Summary: {{summary}}
- Content: {{content}}

Analyse the article and respond strictly in JSON, matching this schema:
{SCHEMA}
IMPORTANT: Reply *only* with the JSON object—no extra explanation.
"""

# Build the LangChain chain: prompt → LLM → JSON parser
prompt = ChatPromptTemplate.from_template(PROMPT)
parser = JsonOutputParser()
analysis_chain = prompt | llm | parser

# ──────────────────────────────────────────────────────────────
# 5. RAG: Retrieve similar past threat analyses for LLM context
# ──────────────────────────────────────────────────────────────
def get_similar_analyses(query_text, top_k=2, max_context_tokens=1500, max_query_tokens=1000):
    """
    Retrieve top_k similar threat analyses from ChromaDB for context augmentation.
    Truncates the query_text before embedding to avoid token overflow.
    Truncates retrieved context snippets to keep prompt lean.
    Because even embedding models have token limits,
    and we don’t want to crash the party with a prompt too big to handle.
    """
    from chromadb_utils import collection

    # Heuristic truncation of query_text for embedding (approximate)
    max_query_chars = max_query_tokens * 4  # Roughly 4 chars per token
    truncated_query = query_text[:max_query_chars]

    results = collection.query(
        query_texts=[truncated_query],  # Use truncated query to keep embedding happy
        n_results=top_k,
        include=['metadatas', 'documents']
    )

    similar_entries = []
    total_tokens = 0

    for meta, doc in zip(results['metadatas'][0], results['documents'][0]):
        snippet = (doc or "")[:250]  # snippet size to save tokens

        entry = (
            f"Title: {meta.get('title')}\n"
            f"Summary Impact: {snippet}\n"
            f"TTPs: {meta.get('ttps')}\n"
            f"Feed Title: {meta.get('feed_title')}\n"
            f"Feed Language: {meta.get('feed_language')}\n"
            f"URL: {meta.get('url')}"
        )

        estimated_tokens = len(entry.split()) * 4 // 3  # rough token estimate

        if total_tokens + estimated_tokens > max_context_tokens:
            # Enough context for now — no need to get greedy
            break

        similar_entries.append(entry)
        total_tokens += estimated_tokens

    if not similar_entries:
        return "None found."

    return "\n\n".join(similar_entries)

# ──────────────────────────────────────────────────────────────
# 6. Main analysis function
# ──────────────────────────────────────────────────────────────
def analyse_and_persist(entry):
    """
    Enriches an ArchiveEntry with LLM analysis, persists to Postgres,
    and stores an embedding in ChromaDB.
    Uses smart truncation in RAG retrieval and prompt construction
    to avoid token overloads and keep the LLM happy.
    Because nobody wants a token overflow error ruining their day.
    """
    # Truncate article content to max 1000 chars to keep prompt manageable
    max_content_length = 1000
    truncated_content = (entry.content or "")[:max_content_length]

    # RAG: Use title, summary, and truncated content for semantic retrieval
    query_text = f"{entry.title} {entry.summary or ''} {truncated_content}"
    retrieved_context = get_similar_analyses(query_text, top_k=2)

    # Prepare prompt inputs (including feed and article metadata)
    inputs = {
        "title": entry.title or "",
        "link": entry.link or "",
        "published": entry.published.isoformat() if entry.published else "",
        "content": truncated_content,
        "summary": entry.summary or "",
        "author": entry.author or "",
        "categories": ", ".join(entry.categories) if entry.categories else "",
        "entry_updated": entry.entry_updated.isoformat() if entry.entry_updated else "",
        "feed_title": entry.feed_title or "",
        "feed_description": entry.feed_description or "",
        "feed_language": entry.feed_language or "",
        "feed_icon": entry.feed_icon or "",
        "feed_updated": entry.feed_updated.isoformat() if entry.feed_updated else "",
        "retrieved_context": retrieved_context,
    }

    # Run the LLM analysis chain
    try:
        result: dict = analysis_chain.invoke(inputs)
    except Exception as e:
        logger.error(f"[red]LLM analysis failed:[/red] {e}")
        return

    # Persist the structured analysis result to Postgres
    session = SessionLocal()
    try:
        analysis = AnalysisEntry(
            guid=entry.guid,
            severity_level=result.get("severity_level"),
            confidence=result.get("confidence"),
            recommended_actions=result.get("recommended_actions"),
            key_IOCs=result.get("key_IOCs"),
            affected_systems_sectors=result.get("affected_systems_sectors"),
            mitigation_strategies=result.get("mitigation_strategies"),
            potential_threat_actors=result.get("potential_threat_actors"),
            historical_context=result.get("historical_context"),
            summary_impact=result.get("summary_impact"),
            relevance=result.get("relevance"),
            additional_notes=result.get("additional_notes"),
            cve_references=result.get("cve_references"),
            ttps=result.get("ttps"),
            attack_vectors=result.get("attack_vectors"),
            tools_used=result.get("tools_used"),
            malware_families=result.get("malware_families"),
            target_geographies=result.get("target_geographies"),
            exploit_references=result.get("exploit_references"),
            source_name=entry.feed_title,
            source_url=entry.feed_url,
            feed_title=entry.feed_title,
            feed_description=entry.feed_description,
            feed_language=entry.feed_language,
            feed_icon=entry.feed_icon,
            feed_updated=entry.feed_updated,
            analysed_at=datetime.utcnow()
        )
        session.add(analysis)
        session.commit()

        # Prepare feed metadata for vector store (for advanced filtering/search)
        feed_metadata = {
            "feed_title": entry.feed_title or "",
            "feed_description": entry.feed_description or "",
            "feed_language": entry.feed_language or "",
            "feed_icon": entry.feed_icon or "",
            "feed_updated": entry.feed_updated.isoformat() if entry.feed_updated else "",
            "feed_url": entry.feed_url or ""
        }

        vector_id = str(uuid.uuid4())
        store_analysis_vector(vector_id, result, entry.title, entry.link, feed_metadata)

    except Exception as e:
        session.rollback()
        logger.error(f"[red]Error persisting analysis:[/red] {e}")
    finally:
        session.close()