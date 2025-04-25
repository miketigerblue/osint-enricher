# enricher/chromadb_utils.py
import chromadb
from chromadb.utils import embedding_functions
import os, json
from config import settings

openai_ef = embedding_functions.OpenAIEmbeddingFunction(
    api_key=settings.openai_api_key,
    model_name="text-embedding-3-large"
)

client = chromadb.PersistentClient(path=settings.chroma_db_path)
collection = client.get_or_create_collection(
    name="threat_embeddings",
    embedding_function=openai_ef
)

def store_analysis_vector(document_id, analysis_result, title, url):
    meta = {"title": title, "url": url}
    # flatten JSON lists/dicts:
    for k,v in analysis_result.items():
        meta[k] = json.dumps(v) if isinstance(v, (list, dict)) else v

    collection.add(
      documents=[analysis_result["summary_impact"]],
      metadatas=[meta],
      ids=[document_id]
    )
