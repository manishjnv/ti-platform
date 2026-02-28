"""RQ Worker tasks — feed ingestion pipeline.

Pattern: fetch → normalize → score → store (PostgreSQL) → index (OpenSearch)
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
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
        stored_items = _bulk_store(session, scored)
        stored = len(stored_items)
        logger.info("store_complete", feed=feed_name, stored=stored)

        # 5. Index in OpenSearch (only newly stored items — avoids duplication)
        ensure_index()
        os_docs = _prepare_os_docs(stored_items) if stored_items else []
        index_result = bulk_index_items(os_docs) if os_docs else {"indexed": 0}
        logger.info("index_complete", feed=feed_name, indexed=index_result.get("indexed", 0))

        # 6. Update state
        # Some connectors (e.g. VT) track their own cursor for rotation
        new_cursor = getattr(connector, "_next_cursor", None) or datetime.now(timezone.utc).isoformat()
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


def sync_attack_techniques() -> dict:
    """Fetch MITRE ATT&CK Enterprise techniques and upsert into DB."""
    from app.services.mitre import fetch_attack_data
    from app.models.models import AttackTechnique

    logger.info("attack_sync_start")
    session = SyncSession()
    try:
        techniques = _run_async(fetch_attack_data())

        upserted = 0
        for t in techniques:
            existing = session.query(AttackTechnique).filter_by(
                id=t["id"], tactic=t["tactic"]
            ).first()

            if existing:
                existing.name = t["name"]
                existing.tactic_label = t["tactic_label"]
                existing.description = t["description"]
                existing.url = t["url"]
                existing.platforms = t["platforms"]
                existing.detection = t["detection"]
                existing.is_subtechnique = t["is_subtechnique"]
                existing.parent_id = t["parent_id"]
                existing.data_sources = t["data_sources"]
                existing.updated_at = datetime.now(timezone.utc)
            else:
                # For multi-tactic techniques, use composite key id+tactic
                # But our PK is just id, so we pick the first tactic
                exists_any = session.query(AttackTechnique).filter_by(id=t["id"]).first()
                if exists_any:
                    continue  # Already stored under a different tactic
                session.add(AttackTechnique(**t))
            upserted += 1

        session.commit()
        logger.info("attack_sync_complete", upserted=upserted, total=len(techniques))
        return {"upserted": upserted, "total_fetched": len(techniques)}

    except Exception as e:
        logger.error("attack_sync_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


def map_intel_to_attack(batch_size: int = 100) -> dict:
    """Auto-map unmapped intel items to ATT&CK techniques based on text analysis."""
    from app.services.mitre import map_intel_item_to_techniques
    from app.models.models import IntelItem, IntelAttackLink, AttackTechnique
    from sqlalchemy import select, exists

    session = SyncSession()
    try:
        # Get all valid technique IDs for validation
        valid_ids = set(
            session.execute(select(AttackTechnique.id)).scalars().all()
        )
        if not valid_ids:
            logger.warning("attack_map_skip", reason="no techniques in DB — run sync_attack_techniques first")
            return {"mapped": 0, "reason": "no techniques"}

        # Get intel items that have NO attack links yet
        already_mapped_subq = (
            select(IntelAttackLink.intel_id)
            .distinct()
            .subquery()
        )
        items = session.execute(
            select(IntelItem)
            .where(~IntelItem.id.in_(select(already_mapped_subq.c.intel_id)))
            .order_by(IntelItem.risk_score.desc())
            .limit(batch_size)
        ).scalars().all()

        total_links = 0
        for item in items:
            item_dict = {
                "title": item.title,
                "summary": item.summary,
                "description": item.description,
                "tags": item.tags,
            }
            technique_ids = map_intel_item_to_techniques(item_dict)

            for tid in technique_ids:
                if tid not in valid_ids:
                    continue
                link = IntelAttackLink(
                    intel_id=item.id,
                    intel_ingested_at=item.ingested_at,
                    technique_id=tid,
                    confidence=60,
                    mapping_type="auto",
                )
                session.add(link)
                total_links += 1

        session.commit()
        logger.info("attack_mapping_complete", items=len(items), links=total_links)
        return {"items_processed": len(items), "links_created": total_links}

    except Exception as e:
        logger.error("attack_mapping_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


def build_relationships(batch_size: int = 200) -> dict:
    """Discover and store implicit relationships between intel items.

    Analyses shared IOCs, CVEs, and ATT&CK techniques to build graph edges.
    """
    from app.services.graph import build_relationships_batch

    logger.info("relationship_build_start")
    session = SyncSession()
    try:
        stats = build_relationships_batch(session, batch_size=batch_size)
        logger.info("relationship_build_complete", **stats)
        return stats
    except Exception as e:
        logger.error("relationship_build_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


def extract_iocs(batch_size: int = 500) -> dict:
    """Extract IOC values from intel items and populate iocs + intel_ioc_links tables.

    Scans intel items with IOC-related asset types, extracts actual IOC values
    from titles/descriptions, upserts into the iocs table, and creates
    intel_ioc_links entries so the relationship graph can discover shared-IOC edges.
    """
    from app.models.models import IntelItem, IOC, IntelIOCLink

    logger.info("ioc_extraction_start")
    session = SyncSession()

    try:
        # Get IOC-type intel items that haven't been linked yet
        linked_subq = (
            select(IntelIOCLink.intel_id)
            .distinct()
            .subquery()
        )

        ioc_asset_types = ("ip", "url", "domain", "hash_sha256", "hash_md5", "hash_sha1")

        items = session.execute(
            select(IntelItem)
            .where(
                IntelItem.asset_type.in_(ioc_asset_types),
                ~IntelItem.id.in_(select(linked_subq.c.intel_id)),
            )
            .order_by(IntelItem.ingested_at.desc())
            .limit(batch_size)
        ).scalars().all()

        if not items:
            logger.info("ioc_extraction_skip", reason="no unlinked IOC items")
            return {"items_processed": 0, "iocs_extracted": 0, "links_created": 0}

        extracted = 0
        linked = 0

        for item in items:
            ioc_values = _extract_ioc_values(item)

            for ioc_val, ioc_type in ioc_values:
                # Upsert IOC record
                ioc_id = uuid.uuid4()
                stmt = pg_insert(IOC).values(
                    id=ioc_id,
                    value=ioc_val,
                    ioc_type=ioc_type,
                    risk_score=item.risk_score,
                    tags=list(item.tags[:5]) if item.tags else [],
                    geo=list(item.geo[:5]) if item.geo else [],
                    source_names=[item.source_name],
                    context={
                        "severity": item.severity,
                        "confidence": item.confidence,
                    },
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["value", "ioc_type"],
                    set_={
                        "last_seen": func.now(),
                        "sighting_count": IOC.sighting_count + 1,
                        "risk_score": stmt.excluded.risk_score,
                        "updated_at": func.now(),
                    },
                )
                session.execute(stmt)

                # Retrieve the IOC id (may be existing record)
                ioc_row_id = session.execute(
                    select(IOC.id).where(IOC.value == ioc_val, IOC.ioc_type == ioc_type)
                ).scalar_one()

                extracted += 1

                # Create intel <-> IOC link
                link_stmt = pg_insert(IntelIOCLink).values(
                    intel_id=item.id,
                    intel_ingested_at=item.ingested_at,
                    ioc_id=ioc_row_id,
                    relationship="indicates",
                )
                link_stmt = link_stmt.on_conflict_do_nothing()
                result = session.execute(link_stmt)
                if result.rowcount > 0:
                    linked += 1

        session.commit()
        logger.info("ioc_extraction_complete", extracted=extracted, linked=linked, items=len(items))
        return {"items_processed": len(items), "iocs_extracted": extracted, "links_created": linked}

    except Exception as e:
        logger.error("ioc_extraction_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


def _extract_ioc_values(item) -> list[tuple[str, str]]:
    """Extract IOC value(s) from an intel item based on source and asset type.

    Returns list of (value, ioc_type) tuples.
    """
    results: list[tuple[str, str]] = []

    # -- Source-specific extraction (most reliable) --------
    if item.source_name == "AbuseIPDB" and item.asset_type == "ip":
        if item.source_ref and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", item.source_ref):
            results.append((item.source_ref, "ip"))
            return results

    if item.source_name == "URLhaus" and item.asset_type == "url":
        # Title: "[URLhaus] Malicious URL: http://..."
        if item.title:
            match = re.search(r"Malicious URL:\s*(https?://\S+)", item.title)
            if match:
                url_val = match.group(1).rstrip(".,;)")
                results.append((url_val, "url"))
                return results
        # Fallback: Description: "Malicious URL detected by URLhaus. URL: {url}. Threat type: ..."
        if item.description:
            match = re.search(r"URL:\s*(https?://[^\s.]+(?:\.[^\s.]+)*(?:/\S*)?)", item.description)
            if match:
                results.append((match.group(1), "url"))
                return results

    # -- OTX extraction: pulse-based items don't carry raw IOC values --------
    # OTX stores 1 intel_item per pulse; the actual IOCs are in the indicators
    # array which isn't stored in the DB. Skip these to avoid false extractions.
    if item.source_name == "OTX" and item.asset_type in ("domain", "hash_sha256", "hash_md5", "hash_sha1", "ip"):
        # OTX title and description rarely contain raw IOC values
        # These items represent threat reports, not individual IOCs
        return results

    # -- Generic regex extraction (fallback) ---------------
    text = f"{item.title or ''} {item.description or ''}"

    if item.asset_type == "ip":
        for ip in set(re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)):
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                results.append((ip, "ip"))

    elif item.asset_type == "url":
        for url in set(re.findall(r"(https?://\S+)", text)):
            results.append((url.rstrip(".,;)"), "url"))

    elif item.asset_type == "domain":
        skip = {"abuse.ch", "alienvault.com", "abuseipdb.com", "nist.gov", "mitre.org", "cisa.gov"}
        for d in set(re.findall(r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z]{2,})+)\b", text, re.I)):
            if d.lower() not in skip:
                results.append((d.lower(), "domain"))

    elif item.asset_type in ("hash_sha256", "hash_md5", "hash_sha1"):
        sha256 = set(re.findall(r"\b([a-f0-9]{64})\b", text, re.I))
        for h in sha256:
            results.append((h.lower(), "hash_sha256"))
        sha1 = set(re.findall(r"\b([a-f0-9]{40})\b", text, re.I))
        for h in sha1:
            if h.lower() not in {s[:40].lower() for s in sha256}:
                results.append((h.lower(), "hash_sha1"))
        md5 = set(re.findall(r"\b([a-f0-9]{32})\b", text, re.I))
        for h in md5:
            results.append((h.lower(), "hash_md5"))

    return results


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


def _bulk_store(session: Session, items: list[dict]) -> list[dict]:
    """Store items in PostgreSQL with dedup.

    TimescaleDB hypertables require unique indexes to include the partition key,
    so we pre-check for existing source_hash values to avoid duplicates.

    Returns the list of actually stored (new) items for downstream indexing.
    """
    from app.models.models import IntelItem
    from sqlalchemy import select

    if not items:
        return []

    # Pre-fetch existing source hashes for fast dedup
    hashes = [item["source_hash"] for item in items]
    existing = set(
        session.execute(
            select(IntelItem.source_hash).where(IntelItem.source_hash.in_(hashes))
        ).scalars().all()
    )

    stored_items: list[dict] = []
    for item in items:
        if item["source_hash"] in existing:
            continue
        try:
            session.add(IntelItem(**item))
            session.flush()
            stored_items.append(item)
            existing.add(item["source_hash"])
        except Exception:
            session.rollback()
            continue

    return stored_items


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
