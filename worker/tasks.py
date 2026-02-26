"""RQ Worker tasks — feed ingestion pipeline.

Pattern: fetch → normalize → score → store (PostgreSQL) → index (OpenSearch)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger, setup_logging
from app.core.opensearch import bulk_index_items, ensure_index
from app.services.scoring import batch_score

setup_logging()
logger = get_logger(__name__)
settings = get_settings()

# Sync engine for RQ worker (RQ is sync)
sync_engine = create_engine(settings.database_url_sync, pool_pre_ping=True, pool_size=5)
SyncSession = sessionmaker(bind=sync_engine)


def _run_async(coro):
    """Run an async coroutine from sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def ingest_feed(feed_name: str) -> dict:
    """Main ingestion task for a single feed.

    Called by RQ scheduler.
    """
    logger.info("ingest_start", feed=feed_name)

    connector = _get_connector(feed_name)
    if not connector:
        logger.error("unknown_feed", feed=feed_name)
        return {"error": f"Unknown feed: {feed_name}"}

    session = SyncSession()
    try:
        # Update state: running
        _update_feed_state(session, feed_name, status="running")
        session.commit()

        # Get last cursor
        state = _get_feed_state(session, feed_name)
        last_cursor = state.last_cursor if state else None

        # 1. Fetch
        raw_items = _run_async(connector.fetch_with_retry(last_cursor))
        logger.info("fetch_complete", feed=feed_name, count=len(raw_items))

        if not raw_items:
            _update_feed_state(session, feed_name, status="success", items_fetched=0, items_stored=0)
            session.commit()
            return {"feed": feed_name, "fetched": 0, "stored": 0}

        # 2. Normalize
        normalized = connector.normalize(raw_items)
        logger.info("normalize_complete", feed=feed_name, count=len(normalized))

        # 3. Score
        scored = batch_score(normalized)

        # 4. Store in PostgreSQL (with dedup)
        stored = _bulk_store(session, scored)
        logger.info("store_complete", feed=feed_name, stored=stored)

        # 5. Index in OpenSearch
        ensure_index()
        os_docs = _prepare_os_docs(scored)
        index_result = bulk_index_items(os_docs)
        logger.info("index_complete", feed=feed_name, indexed=index_result.get("indexed", 0))

        # 6. Update state
        new_cursor = datetime.now(timezone.utc).isoformat()
        _update_feed_state(
            session, feed_name,
            status="success",
            last_cursor=new_cursor,
            items_fetched=len(raw_items),
            items_stored=stored,
        )
        session.commit()

        result = {
            "feed": feed_name,
            "fetched": len(raw_items),
            "normalized": len(normalized),
            "stored": stored,
            "indexed": index_result.get("indexed", 0),
        }
        logger.info("ingest_complete", **result)
        return result

    except Exception as e:
        logger.error("ingest_error", feed=feed_name, error=str(e))
        session.rollback()
        try:
            _update_feed_state(session, feed_name, status="failed", error_message=str(e)[:500])
            session.commit()
        except Exception:
            pass
        return {"error": str(e), "feed": feed_name}
    finally:
        session.close()
        try:
            _run_async(connector.close())
        except RuntimeError:
            pass  # Event loop closed — httpx client already cleaned up


def ingest_all_feeds() -> list[dict]:
    """Ingest all feeds sequentially."""
    feeds = ["cisa_kev", "nvd", "urlhaus", "abuseipdb", "otx", "virustotal", "shodan"]
    results = []
    for feed in feeds:
        result = ingest_feed(feed)
        results.append(result)
    return results


def refresh_materialized_views() -> dict:
    """Refresh dashboard materialized views."""
    from sqlalchemy import text
    session = SyncSession()
    try:
        session.execute(text("SELECT refresh_dashboard_views()"))
        session.commit()
        logger.info("materialized_views_refreshed")
        return {"status": "ok"}
    except Exception as e:
        logger.error("mv_refresh_error", error=str(e))
        return {"error": str(e)}
    finally:
        session.close()


def generate_ai_summaries(batch_size: int = 10) -> dict:
    """Generate AI summaries for items that don't have one."""
    from app.services.ai import generate_summary

    session = SyncSession()
    try:
        from app.models.models import IntelItem
        from sqlalchemy import select

        # Get items without AI summary, ordered by risk score
        items = session.execute(
            select(IntelItem)
            .where(IntelItem.ai_summary.is_(None))
            .order_by(IntelItem.risk_score.desc())
            .limit(batch_size)
        ).scalars().all()

        generated = 0
        for item in items:
            summary = _run_async(generate_summary(
                title=item.title,
                description=item.description,
                severity=item.severity,
                source_name=item.source_name,
                cve_ids=item.cve_ids,
            ))
            if summary:
                item.ai_summary = summary
                item.ai_summary_at = datetime.now(timezone.utc)
                generated += 1

        session.commit()
        logger.info("ai_summaries_generated", count=generated)
        return {"generated": generated, "total": len(items)}

    except Exception as e:
        logger.error("ai_summary_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


# ─── Helpers ──────────────────────────────────────────────

def _get_connector(feed_name: str):
    """Factory for feed connectors."""
    from app.services.feeds.nvd import NVDConnector
    from app.services.feeds.kev import CISAKEVConnector
    from app.services.feeds.urlhaus import URLhausConnector
    from app.services.feeds.abuseipdb import AbuseIPDBConnector
    from app.services.feeds.otx import OTXConnector
    from app.services.feeds.virustotal import VirusTotalConnector
    from app.services.feeds.shodan import ShodanConnector

    connectors = {
        "nvd": NVDConnector,
        "cisa_kev": CISAKEVConnector,
        "urlhaus": URLhausConnector,
        "abuseipdb": AbuseIPDBConnector,
        "otx": OTXConnector,
        "virustotal": VirusTotalConnector,
        "shodan": ShodanConnector,
    }
    cls = connectors.get(feed_name)
    return cls() if cls else None


def _get_feed_state(session: Session, feed_name: str):
    from app.models.models import FeedSyncState
    return session.query(FeedSyncState).filter_by(feed_name=feed_name).first()


def _update_feed_state(
    session: Session,
    feed_name: str,
    *,
    status: str = "idle",
    last_cursor: str | None = None,
    items_fetched: int = 0,
    items_stored: int = 0,
    error_message: str | None = None,
) -> None:
    state = _get_feed_state(session, feed_name)
    if not state:
        return

    now = datetime.now(timezone.utc)
    state.status = status
    state.last_run = now
    state.updated_at = now

    if status == "success":
        state.last_success = now
    if last_cursor is not None:
        state.last_cursor = last_cursor
    state.items_fetched = items_fetched
    state.items_stored = items_stored
    state.error_message = error_message
    state.run_count = (state.run_count or 0) + 1


def _bulk_store(session: Session, items: list[dict]) -> int:
    """Store items in PostgreSQL with dedup."""
    from app.models.models import IntelItem
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    stored = 0
    for item in items:
        stmt = pg_insert(IntelItem.__table__).values(**item)
        stmt = stmt.on_conflict_do_nothing(index_elements=["source_hash"])
        result = session.execute(stmt)
        if result.rowcount > 0:
            stored += 1

    return stored


def _prepare_os_docs(items: list[dict]) -> list[dict]:
    """Prepare items for OpenSearch indexing."""
    docs = []
    for item in items:
        doc = {
            "id": str(item["id"]),
            "title": item.get("title", ""),
            "summary": item.get("summary", ""),
            "description": item.get("description", ""),
            "published_at": item.get("published_at").isoformat() if item.get("published_at") else None,
            "ingested_at": item.get("ingested_at").isoformat() if item.get("ingested_at") else None,
            "severity": item.get("severity", "unknown"),
            "risk_score": item.get("risk_score", 0),
            "confidence": item.get("confidence", 50),
            "source_name": item.get("source_name", ""),
            "source_url": item.get("source_url", ""),
            "source_reliability": item.get("source_reliability", 50),
            "source_ref": item.get("source_ref", ""),
            "feed_type": item.get("feed_type", ""),
            "asset_type": item.get("asset_type", "other"),
            "tlp": item.get("tlp", "TLP:CLEAR"),
            "tags": item.get("tags", []),
            "geo": item.get("geo", []),
            "industries": item.get("industries", []),
            "cve_ids": item.get("cve_ids", []),
            "affected_products": item.get("affected_products", []),
            "related_ioc_count": item.get("related_ioc_count", 0),
            "is_kev": item.get("is_kev", False),
            "exploit_available": item.get("exploit_available", False),
            "exploitability_score": item.get("exploitability_score"),
            "source_hash": item.get("source_hash", ""),
        }
        docs.append(doc)
    return docs
