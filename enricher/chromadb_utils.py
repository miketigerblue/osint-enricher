"""
ChromaDB utilities for storing and retrieving threat analysis vectors.

- Initializes ChromaDB client and collection with OpenAI embedding function.
- Stores analysis results as embeddings with rich metadata for RAG and filtering.
- Includes feed/source metadata in vector metadata for advanced search/filtering.
"""

import chromadb
from chromadb.utils import embedding_functions
import json
from config import settings

# ──────────────────────────────────────────────────────────────
# 1. Embedding Function Setup
# ──────────────────────────────────────────────────────────────

# Use OpenAI's embedding model for vectorization
openai_ef = embedding_functions.OpenAIEmbeddingFunction(
    api_key=settings.openai_api_key,
    model_name="text-embedding-3-large"
)

# ──────────────────────────────────────────────────────────────
# 2. ChromaDB Client and Collection Setup
# ──────────────────────────────────────────────────────────────

# Persistent ChromaDB client (vector DB)
client = chromadb.PersistentClient(path=settings.chroma_db_path)

# Collection for threat embeddings, with embedding function
collection = client.get_or_create_collection(
    name="threat_embeddings",
    embedding_function=openai_ef
)

# ──────────────────────────────────────────────────────────────
# 3. Store Analysis Vector Function
# ──────────────────────────────────────────────────────────────

def store_analysis_vector(document_id: str, analysis_result: dict, title: str, url: str, feed_metadata: dict = None) -> None:
    """
    Store the analysis result as an embedding vector in ChromaDB.

    - Embeds a concatenation of key fields for semantic search.
    - Stores all fields as metadata for advanced filtering.
    - Includes feed/source metadata if provided.
    """
    # Prepare metadata for filtering/search (flatten arrays/dicts)
    meta = {
        "title": title,
        "url": url,
        "severity_level": analysis_result.get("severity_level"),
        "confidence": analysis_result.get("confidence"),
        "summary_impact": analysis_result.get("summary_impact"),
        "relevance": analysis_result.get("relevance"),
        "cve_references": json.dumps(analysis_result.get("cve_references", [])),
        "ttps": json.dumps(analysis_result.get("ttps", [])),
        "attack_vectors": json.dumps(analysis_result.get("attack_vectors", [])),
        "tools_used": json.dumps(analysis_result.get("tools_used", [])),
        "malware_families": json.dumps(analysis_result.get("malware_families", [])),
        "target_geographies": json.dumps(analysis_result.get("target_geographies", [])),
        "exploit_references": json.dumps(analysis_result.get("exploit_references", [])),
    }
    # Add any other fields from analysis_result (flatten if list/dict)
    for k, v in analysis_result.items():
        if k not in meta:
            meta[k] = json.dumps(v) if isinstance(v, (list, dict)) else v

    # Add feed/source metadata if provided
    if feed_metadata:
        meta.update(feed_metadata)

    # Compose a rich context string for embedding (includes feed metadata)
    doc_for_embedding = (
        f"Title: {title}\n"
        f"Summary Impact: {analysis_result.get('summary_impact', '')}\n"
        f"Key IOCs: {', '.join(analysis_result.get('key_IOCs', []) or [])}\n"
        f"Mitigations: {', '.join(analysis_result.get('mitigation_strategies', []) or [])}\n"
        f"TTPs: {', '.join(analysis_result.get('ttps', []) or [])}\n"
        f"Attack Vectors: {', '.join(analysis_result.get('attack_vectors', []) or [])}\n"
        f"Tools: {', '.join(analysis_result.get('tools_used', []) or [])}\n"
        f"Malware: {', '.join(analysis_result.get('malware_families', []) or [])}\n"
        f"Historical Context: {analysis_result.get('historical_context', '')}\n"
        f"Feed Title: {feed_metadata.get('feed_title') if feed_metadata else ''}\n"
        f"Feed Description: {feed_metadata.get('feed_description') if feed_metadata else ''}\n"
        f"Feed Language: {feed_metadata.get('feed_language') if feed_metadata else ''}\n"
    )

    # Store the vector and metadata in ChromaDB
    try:
        collection.add(
            documents=[doc_for_embedding],
            metadatas=[meta],
            ids=[document_id]
        )
    except Exception as e:
        print(f"Failed to store analysis vector for {document_id}: {e}")