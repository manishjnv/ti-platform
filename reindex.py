"""One-time script to reindex all PostgreSQL intel items into OpenSearch.

Run inside the API container:
  docker cp reindex.py ti-platform-api-1:/app/api/reindex.py
  docker exec ti-platform-api-1 python /app/api/reindex.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import asyncio
from app.core.opensearch import ensure_index, bulk_index_items, opensearch_client, INDEX_NAME
from app.core.database import engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text


async def reindex():
    ensure_index()
    print("Index ready")

    async with AsyncSession(engine) as db:
        result = await db.execute(text("SELECT COUNT(*) FROM intel_items"))
        total = result.scalar()
        print(f"Total items: {total}")

        batch_size = 500
        offset = 0
        indexed = 0

        while offset < total:
            q = text(
                "SELECT id, title, summary, description, published_at, ingested_at, "
                "severity, risk_score, confidence, source_name, source_url, "
                "source_reliability, source_ref, feed_type, asset_type, tlp, "
                "tags, geo, industries, cve_ids, affected_products, "
                "related_ioc_count, is_kev, exploit_available, "
                "exploitability_score, source_hash "
                "FROM intel_items ORDER BY ingested_at LIMIT :lim OFFSET :off"
            )
            result = await db.execute(q, {"lim": batch_size, "off": offset})
            rows = result.fetchall()
            if not rows:
                break

            docs = []
            for r in rows:
                doc = {
                    "id": str(r.id),
                    "title": r.title or "",
                    "summary": r.summary or "",
                    "description": r.description or "",
                    "published_at": r.published_at.isoformat() if r.published_at else None,
                    "ingested_at": r.ingested_at.isoformat() if r.ingested_at else None,
                    "severity": r.severity or "unknown",
                    "risk_score": r.risk_score or 0,
                    "confidence": r.confidence or 50,
                    "source_name": r.source_name or "",
                    "source_url": r.source_url or "",
                    "source_reliability": r.source_reliability or 50,
                    "source_ref": r.source_ref or "",
                    "feed_type": r.feed_type or "",
                    "asset_type": r.asset_type or "other",
                    "tlp": r.tlp or "TLP:CLEAR",
                    "tags": r.tags or [],
                    "geo": r.geo or [],
                    "industries": r.industries or [],
                    "cve_ids": r.cve_ids or [],
                    "affected_products": r.affected_products or [],
                    "related_ioc_count": r.related_ioc_count or 0,
                    "is_kev": bool(r.is_kev),
                    "exploit_available": bool(r.exploit_available),
                    "exploitability_score": r.exploitability_score,
                    "source_hash": r.source_hash or "",
                }
                docs.append(doc)

            res = bulk_index_items(docs)
            indexed += len(docs)
            offset += batch_size
            errs = res.get("errors", False)
            print(f"  Indexed {indexed}/{total} errors={errs}")

    cnt = opensearch_client.count(index=INDEX_NAME)
    print(f"Final OS count: {cnt['count']}")


asyncio.run(reindex())
