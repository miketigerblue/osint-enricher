# enricher/chromadb_utils.py

import os
import json
import logging

import chromadb
from chromadb.utils import embedding_functions

from config import settings

logger = logging.getLogger(__name__)

# Setup OpenAI embedding function
openai_ef = embedding_functions.OpenAIEmbeddingFunction(
    api_key    = settings.openai_api_key,
    model_name = "text-embedding-3-large"
)

client = chromadb.PersistentClient(path=settings.chroma_db_path)
collection = client.get_or_create_collection(
    name               = "threat_embeddings",
    embedding_function = openai_ef
)

def store_analysis_vector(document_id, analysis_result, title, url):
    """
    Add a new embedding + metadata to ChromaDB.
    """
    meta = {"title": title, "url": url}
    for k, v in analysis_result.items():
        meta[k] = json.dumps(v) if isinstance(v, (list, dict)) else v

    logger.debug(f"Storing embedding for {document_id}")
    collection.add(
        documents = [analysis_result.get("summary_impact", "")],
        metadatas = [meta],
        ids       = [document_id]
    )
    logger.info(f"ChromaDB vector stored: {document_id}")
