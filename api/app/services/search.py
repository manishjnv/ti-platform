"""Search service — OpenSearch-backed global IOC search with type auto-detection."""

from __future__ import annotations

import re

from app.core.logging import get_logger
from app.core.opensearch import search_intel, INDEX_NAME
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings

logger = get_logger(__name__)
settings = get_settings()

# Regex patterns for IOC type detection
IOC_PATTERNS = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    "ip": re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "domain": re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"),
    "url": re.compile(r"^https?://", re.IGNORECASE),
    "hash_md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "hash_sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "hash_sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
}


def detect_ioc_type(query: str) -> str | None:
    """Auto-detect the type of an IOC from the search query."""
    q = query.strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.match(q):
            return ioc_type
    return None


async def global_search(
    query: str,
    *,
    feed_type: str | None = None,
    severity: str | None = None,
    asset_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> dict:
    """Execute a global search across intel items.

    Returns paginated results with detected IOC type.
    """
    # Check cache
    ck = cache_key("search", query, feed_type, severity, asset_type, page, page_size)
    cached = await get_cached(ck)
    if cached:
        return cached

    detected_type = detect_ioc_type(query)
    from_ = (page - 1) * page_size

    # Build OpenSearch query
    os_query = _build_query(
        query, detected_type, feed_type, severity, asset_type, date_from, date_to
    )

    try:
        result = search_intel(os_query, size=page_size, from_=from_)
    except Exception as e:
        logger.error("opensearch_search_error", error=str(e))
        return {
            "results": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "pages": 0,
            "query": query,
            "detected_type": detected_type,
        }

    hits = result.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = []

    for hit in hits.get("hits", []):
        source = hit["_source"]
        source["id"] = hit["_id"]
        items.append(source)

    response = {
        "results": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "query": query,
        "detected_type": detected_type,
    }

    # Cache for configured TTL
    await set_cached(ck, response, ttl=settings.cache_ttl_search)
    return response


def _build_query(
    query: str,
    detected_type: str | None,
    feed_type: str | None,
    severity: str | None,
    asset_type: str | None,
    date_from: str | None,
    date_to: str | None,
) -> dict:
    """Build an OpenSearch query body."""
    must = []
    filters = []

    # Main query — use match on detected type or multi_match.
    # After index rebuild, keyword fields (cve_ids, source_ref, tags, etc.)
    # are properly mapped as keyword type — use term queries on bare field names.
    if detected_type == "cve":
        must.append({
            "bool": {
                "should": [
                    {"term": {"cve_ids": query.upper()}},
                    {"match_phrase": {"title": query.upper()}},
                    {"match_phrase": {"description": query.upper()}},
                ],
                "minimum_should_match": 1,
            }
        })
    elif detected_type == "ip":
        must.append({
            "bool": {
                "should": [
                    {"term": {"source_ref": query}},
                    {"match_phrase": {"title": query}},
                    {"match_phrase": {"description": query}},
                ],
                "minimum_should_match": 1,
            }
        })
    elif detected_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        must.append({
            "bool": {
                "should": [
                    {"term": {"source_ref": query.lower()}},
                    {"match_phrase": {"description": query}},
                ],
                "minimum_should_match": 1,
            }
        })
    else:
        # For generic queries, search text fields with multi_match (supports
        # fuzziness) and keyword fields with separate term/wildcard clauses.
        must.append({
            "bool": {
                "should": [
                    {
                        "multi_match": {
                            "query": query,
                            "fields": ["title^3", "summary^2", "description"],
                            "type": "best_fields",
                            "fuzziness": "AUTO",
                        }
                    },
                    {"term": {"cve_ids": {"value": query.upper(), "boost": 4}}},
                    {"term": {"tags": {"value": query, "boost": 2}}},
                    {"term": {"source_ref": query}},
                    {"term": {"affected_products": query}},
                ],
                "minimum_should_match": 1,
            }
        })

    # Filters — keyword fields use bare field names
    if feed_type:
        filters.append({"term": {"feed_type": feed_type}})
    if severity:
        filters.append({"term": {"severity": severity}})
    if asset_type:
        filters.append({"term": {"asset_type": asset_type}})

    # Date range
    if date_from or date_to:
        date_range: dict = {}
        if date_from:
            date_range["gte"] = date_from
        if date_to:
            date_range["lte"] = date_to
        filters.append({"range": {"published_at": date_range}})

    return {
        "query": {
            "bool": {
                "must": must,
                "filter": filters,
            }
        },
        "sort": [
            {"risk_score": {"order": "desc"}},
            {"ingested_at": {"order": "desc"}},
        ],
        "highlight": {
            "fields": {
                "title": {},
                "summary": {},
                "description": {"fragment_size": 200},
            }
        },
    }
