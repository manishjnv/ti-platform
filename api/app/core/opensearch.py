"""OpenSearch client setup and index management."""

from __future__ import annotations

import json
from pathlib import Path

from opensearchpy import OpenSearch

from app.core.config import get_settings

settings = get_settings()

opensearch_client = OpenSearch(
    hosts=[settings.opensearch_url],
    http_auth=(settings.opensearch_user, settings.opensearch_password),
    use_ssl=settings.opensearch_url.startswith("https"),
    verify_certs=settings.opensearch_verify_certs,
    ssl_show_warn=False,
    timeout=30,
)

INDEX_NAME = settings.opensearch_index


def ensure_index() -> None:
    """Create the intel-items index if it doesn't exist."""
    if not opensearch_client.indices.exists(index=INDEX_NAME):
        mapping_path = Path(__file__).resolve().parents[3] / "opensearch" / "intel-items-mapping.json"
        if mapping_path.exists():
            with open(mapping_path) as f:
                body = json.load(f)
        else:
            body = {
                "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
                "mappings": {"properties": {"title": {"type": "text"}, "id": {"type": "keyword"}}},
            }
        opensearch_client.indices.create(index=INDEX_NAME, body=body)


def index_intel_item(doc_id: str, document: dict) -> None:
    """Index a single intel item."""
    opensearch_client.index(index=INDEX_NAME, id=doc_id, body=document, refresh="wait_for")


def bulk_index_items(documents: list[dict]) -> dict:
    """Bulk index multiple items."""
    if not documents:
        return {"indexed": 0}

    body = []
    for doc in documents:
        body.append({"index": {"_index": INDEX_NAME, "_id": doc["id"]}})
        body.append(doc)

    result = opensearch_client.bulk(body=body, refresh="wait_for")
    return {"indexed": len(documents), "errors": result.get("errors", False)}


def search_intel(query: dict, size: int = 20, from_: int = 0) -> dict:
    """Execute a search query against intel items."""
    return opensearch_client.search(
        index=INDEX_NAME,
        body=query,
        size=size,
        from_=from_,
    )


def delete_index() -> None:
    """Delete the index (for testing/reset)."""
    if opensearch_client.indices.exists(index=INDEX_NAME):
        opensearch_client.indices.delete(index=INDEX_NAME)


def rebuild_index() -> dict:
    """Delete and recreate the index with the proper mapping from the mapping file.

    This fixes the mapping mismatch where keyword fields were auto-detected as text.
    After calling this, all data must be re-indexed from PostgreSQL.
    """
    existed = opensearch_client.indices.exists(index=INDEX_NAME)
    if existed:
        opensearch_client.indices.delete(index=INDEX_NAME)

    mapping_path = Path(__file__).resolve().parents[3] / "opensearch" / "intel-items-mapping.json"
    if mapping_path.exists():
        with open(mapping_path) as f:
            body = json.load(f)
    else:
        raise FileNotFoundError(f"Mapping file not found: {mapping_path}")

    opensearch_client.indices.create(index=INDEX_NAME, body=body)
    return {"status": "rebuilt", "index": INDEX_NAME, "previously_existed": existed}
