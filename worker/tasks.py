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
    feeds = ["cisa_kev", "nvd", "urlhaus", "abuseipdb", "otx", "virustotal", "shodan", "threatfox", "malwarebazaar"]
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


def remap_all_intel_to_attack() -> dict:
    """Delete all auto-mapped ATT&CK links and re-map ALL intel items.

    Used when the keyword map is updated to rebuild all technique mappings.
    """
    from app.services.mitre import map_intel_item_to_techniques
    from app.models.models import IntelItem, IntelAttackLink, AttackTechnique
    from sqlalchemy import delete

    session = SyncSession()
    try:
        # Get all valid technique IDs
        valid_ids = set(
            session.execute(select(AttackTechnique.id)).scalars().all()
        )
        if not valid_ids:
            return {"error": "no techniques in DB"}

        # Delete all existing auto-mapped links (preserve manual ones)
        del_result = session.execute(
            delete(IntelAttackLink).where(IntelAttackLink.mapping_type == "auto")
        )
        deleted = del_result.rowcount
        logger.info("remap_cleared_auto_links", deleted=deleted)

        # Process ALL intel items in batches
        total_items = 0
        total_links = 0
        offset = 0
        batch_size = 500

        while True:
            items = session.execute(
                select(IntelItem)
                .order_by(IntelItem.ingested_at.desc())
                .offset(offset)
                .limit(batch_size)
            ).scalars().all()

            if not items:
                break

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
                    session.merge(link)
                    total_links += 1

            total_items += len(items)
            offset += batch_size
            # Commit in batches to avoid huge transactions
            session.commit()
            logger.info("remap_batch", items_so_far=total_items, links_so_far=total_links)

        logger.info("remap_complete", total_items=total_items, total_links=total_links, deleted_old=deleted)
        return {"items_processed": total_items, "links_created": total_links, "old_links_deleted": deleted}

    except Exception as e:
        logger.error("remap_error", error=str(e))
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


# ─── Notification Evaluation ──────────────────────────────

def evaluate_notification_rules(lookback_minutes: int = 10) -> dict:
    """Evaluate all active notification rules against recent data.

    Checks threshold rules (severity, risk, KEV), feed health, and
    cross-feed correlation. Creates in-app notifications for matches.
    Also ensures system default rules exist for all users.
    """
    from app.services.notifications import (
        ensure_system_rules,
        evaluate_notification_rules as _evaluate,
    )

    logger.info("notification_eval_start", lookback_minutes=lookback_minutes)
    session = SyncSession()
    try:
        # Ensure every user has system rules (idempotent)
        ensure_system_rules(session)

        # Run rule evaluation
        stats = _evaluate(session, lookback_minutes=lookback_minutes)
        return stats
    except Exception as e:
        logger.error("notification_eval_error", error=str(e))
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
    from app.services.feeds.threatfox import ThreatFoxConnector
    from app.services.feeds.malwarebazaar import MalwareBazaarConnector

    connectors = {
        "nvd": NVDConnector,
        "cisa_kev": CISAKEVConnector,
        "urlhaus": URLhausConnector,
        "abuseipdb": AbuseIPDBConnector,
        "otx": OTXConnector,
        "virustotal": VirusTotalConnector,
        "shodan": ShodanConnector,
        "threatfox": ThreatFoxConnector,
        "malwarebazaar": MalwareBazaarConnector,
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
            "updated_at": item.get("updated_at").isoformat() if item.get("updated_at") else item.get("ingested_at").isoformat() if item.get("ingested_at") else None,
            "ai_summary": item.get("ai_summary", ""),
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


# ── IPinfo Lite IP Enrichment ────────────────────────────

# Country-code → continent mapping (ISO 3166 / UN M49 groupings)
_CC_CONTINENT: dict[str, tuple[str, str]] = {
    "AF": ("AS", "Asia"), "AX": ("EU", "Europe"), "AL": ("EU", "Europe"), "DZ": ("AF", "Africa"),
    "AS": ("OC", "Oceania"), "AD": ("EU", "Europe"), "AO": ("AF", "Africa"), "AI": ("NA", "North America"),
    "AQ": ("AN", "Antarctica"), "AG": ("NA", "North America"), "AR": ("SA", "South America"),
    "AM": ("AS", "Asia"), "AW": ("NA", "North America"), "AU": ("OC", "Oceania"), "AT": ("EU", "Europe"),
    "AZ": ("AS", "Asia"), "BS": ("NA", "North America"), "BH": ("AS", "Asia"), "BD": ("AS", "Asia"),
    "BB": ("NA", "North America"), "BY": ("EU", "Europe"), "BE": ("EU", "Europe"), "BZ": ("NA", "North America"),
    "BJ": ("AF", "Africa"), "BM": ("NA", "North America"), "BT": ("AS", "Asia"), "BO": ("SA", "South America"),
    "BA": ("EU", "Europe"), "BW": ("AF", "Africa"), "BR": ("SA", "South America"), "BN": ("AS", "Asia"),
    "BG": ("EU", "Europe"), "BF": ("AF", "Africa"), "BI": ("AF", "Africa"), "KH": ("AS", "Asia"),
    "CM": ("AF", "Africa"), "CA": ("NA", "North America"), "CV": ("AF", "Africa"), "KY": ("NA", "North America"),
    "CF": ("AF", "Africa"), "TD": ("AF", "Africa"), "CL": ("SA", "South America"), "CN": ("AS", "Asia"),
    "CO": ("SA", "South America"), "KM": ("AF", "Africa"), "CG": ("AF", "Africa"), "CD": ("AF", "Africa"),
    "CR": ("NA", "North America"), "CI": ("AF", "Africa"), "HR": ("EU", "Europe"), "CU": ("NA", "North America"),
    "CY": ("EU", "Europe"), "CZ": ("EU", "Europe"), "DK": ("EU", "Europe"), "DJ": ("AF", "Africa"),
    "DM": ("NA", "North America"), "DO": ("NA", "North America"), "EC": ("SA", "South America"),
    "EG": ("AF", "Africa"), "SV": ("NA", "North America"), "GQ": ("AF", "Africa"), "ER": ("AF", "Africa"),
    "EE": ("EU", "Europe"), "ET": ("AF", "Africa"), "FJ": ("OC", "Oceania"), "FI": ("EU", "Europe"),
    "FR": ("EU", "Europe"), "GA": ("AF", "Africa"), "GM": ("AF", "Africa"), "GE": ("AS", "Asia"),
    "DE": ("EU", "Europe"), "GH": ("AF", "Africa"), "GR": ("EU", "Europe"), "GD": ("NA", "North America"),
    "GT": ("NA", "North America"), "GN": ("AF", "Africa"), "GW": ("AF", "Africa"), "GY": ("SA", "South America"),
    "HT": ("NA", "North America"), "HN": ("NA", "North America"), "HK": ("AS", "Asia"), "HU": ("EU", "Europe"),
    "IS": ("EU", "Europe"), "IN": ("AS", "Asia"), "ID": ("AS", "Asia"), "IR": ("AS", "Asia"),
    "IQ": ("AS", "Asia"), "IE": ("EU", "Europe"), "IL": ("AS", "Asia"), "IT": ("EU", "Europe"),
    "JM": ("NA", "North America"), "JP": ("AS", "Asia"), "JO": ("AS", "Asia"), "KZ": ("AS", "Asia"),
    "KE": ("AF", "Africa"), "KI": ("OC", "Oceania"), "KP": ("AS", "Asia"), "KR": ("AS", "Asia"),
    "KW": ("AS", "Asia"), "KG": ("AS", "Asia"), "LA": ("AS", "Asia"), "LV": ("EU", "Europe"),
    "LB": ("AS", "Asia"), "LS": ("AF", "Africa"), "LR": ("AF", "Africa"), "LY": ("AF", "Africa"),
    "LI": ("EU", "Europe"), "LT": ("EU", "Europe"), "LU": ("EU", "Europe"), "MO": ("AS", "Asia"),
    "MK": ("EU", "Europe"), "MG": ("AF", "Africa"), "MW": ("AF", "Africa"), "MY": ("AS", "Asia"),
    "MV": ("AS", "Asia"), "ML": ("AF", "Africa"), "MT": ("EU", "Europe"), "MH": ("OC", "Oceania"),
    "MR": ("AF", "Africa"), "MU": ("AF", "Africa"), "MX": ("NA", "North America"), "FM": ("OC", "Oceania"),
    "MD": ("EU", "Europe"), "MC": ("EU", "Europe"), "MN": ("AS", "Asia"), "ME": ("EU", "Europe"),
    "MA": ("AF", "Africa"), "MZ": ("AF", "Africa"), "MM": ("AS", "Asia"), "NA": ("AF", "Africa"),
    "NR": ("OC", "Oceania"), "NP": ("AS", "Asia"), "NL": ("EU", "Europe"), "NZ": ("OC", "Oceania"),
    "NI": ("NA", "North America"), "NE": ("AF", "Africa"), "NG": ("AF", "Africa"), "NO": ("EU", "Europe"),
    "OM": ("AS", "Asia"), "PK": ("AS", "Asia"), "PW": ("OC", "Oceania"), "PS": ("AS", "Asia"),
    "PA": ("NA", "North America"), "PG": ("OC", "Oceania"), "PY": ("SA", "South America"),
    "PE": ("SA", "South America"), "PH": ("AS", "Asia"), "PL": ("EU", "Europe"), "PT": ("EU", "Europe"),
    "QA": ("AS", "Asia"), "RO": ("EU", "Europe"), "RU": ("EU", "Europe"), "RW": ("AF", "Africa"),
    "SA": ("AS", "Asia"), "SN": ("AF", "Africa"), "RS": ("EU", "Europe"), "SC": ("AF", "Africa"),
    "SL": ("AF", "Africa"), "SG": ("AS", "Asia"), "SK": ("EU", "Europe"), "SI": ("EU", "Europe"),
    "SB": ("OC", "Oceania"), "SO": ("AF", "Africa"), "ZA": ("AF", "Africa"), "ES": ("EU", "Europe"),
    "LK": ("AS", "Asia"), "SD": ("AF", "Africa"), "SR": ("SA", "South America"), "SZ": ("AF", "Africa"),
    "SE": ("EU", "Europe"), "CH": ("EU", "Europe"), "SY": ("AS", "Asia"), "TW": ("AS", "Asia"),
    "TJ": ("AS", "Asia"), "TZ": ("AF", "Africa"), "TH": ("AS", "Asia"), "TL": ("AS", "Asia"),
    "TG": ("AF", "Africa"), "TO": ("OC", "Oceania"), "TT": ("NA", "North America"), "TN": ("AF", "Africa"),
    "TR": ("AS", "Asia"), "TM": ("AS", "Asia"), "TV": ("OC", "Oceania"), "UG": ("AF", "Africa"),
    "UA": ("EU", "Europe"), "AE": ("AS", "Asia"), "GB": ("EU", "Europe"), "US": ("NA", "North America"),
    "UY": ("SA", "South America"), "UZ": ("AS", "Asia"), "VU": ("OC", "Oceania"), "VE": ("SA", "South America"),
    "VN": ("AS", "Asia"), "YE": ("AS", "Asia"), "ZM": ("AF", "Africa"), "ZW": ("AF", "Africa"),
}

# ISO 3166 country-code → full country name
_CC_NAMES: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AD": "Andorra", "AO": "Angola",
    "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia", "AU": "Australia",
    "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh",
    "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize", "BJ": "Benin",
    "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana",
    "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi",
    "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada", "CV": "Cape Verde", "CF": "Central African Republic",
    "TD": "Chad", "CL": "Chile", "CN": "China", "CO": "Colombia", "KM": "Comoros",
    "CG": "Congo", "CD": "DR Congo", "CR": "Costa Rica", "CI": "Ivory Coast", "HR": "Croatia",
    "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti",
    "DM": "Dominica", "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt",
    "SV": "El Salvador", "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia",
    "ET": "Ethiopia", "FJ": "Fiji", "FI": "Finland", "FR": "France", "GA": "Gabon", "GM": "Gambia",
    "GE": "Georgia", "DE": "Germany", "GH": "Ghana", "GR": "Greece", "GD": "Grenada",
    "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti",
    "HN": "Honduras", "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India",
    "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel", "IT": "Italy",
    "JM": "Jamaica", "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KI": "Kiribati", "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan",
    "LA": "Laos", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia", "LY": "Libya",
    "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg", "MO": "Macau", "MK": "North Macedonia",
    "MG": "Madagascar", "MW": "Malawi", "MY": "Malaysia", "MV": "Maldives", "ML": "Mali",
    "MT": "Malta", "MH": "Marshall Islands", "MR": "Mauritania", "MU": "Mauritius", "MX": "Mexico",
    "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro",
    "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru",
    "NP": "Nepal", "NL": "Netherlands", "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger",
    "NG": "Nigeria", "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau",
    "PS": "Palestine", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru",
    "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "RO": "Romania",
    "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
    "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SZ": "Eswatini", "SE": "Sweden", "CH": "Switzerland",
    "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan", "TZ": "Tanzania", "TH": "Thailand",
    "TL": "Timor-Leste", "TG": "Togo", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia",
    "TR": "Turkey", "TM": "Turkmenistan", "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine",
    "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VU": "Vanuatu", "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen",
    "ZM": "Zambia", "ZW": "Zimbabwe",
}

IPINFO_BASE = "https://ipinfo.io"
IPINFO_TIMEOUT = 10


def enrich_ips_ipinfo(batch_size: int = 100) -> dict:
    """Batch-enrich IP-type IOCs with ASN/geo data from IPinfo.

    Picks up to `batch_size` IP IOCs that have NOT been enriched yet
    (enriched_at IS NULL) and calls the IPinfo API for each.
    """
    from app.models.models import IOC as IOCModel

    logger.info("ipinfo_enrichment_start", batch_size=batch_size)
    session = SyncSession()

    try:
        ips = session.execute(
            select(IOCModel)
            .where(IOCModel.ioc_type == "ip", IOCModel.enriched_at.is_(None))
            .order_by(IOCModel.created_at.asc())
            .limit(batch_size)
        ).scalars().all()

        if not ips:
            logger.info("ipinfo_enrichment_skip", reason="no unenriched IPs")
            return {"enriched": 0, "errors": 0}

        enriched = 0
        errors = 0
        token = settings.ipinfo_token

        for ioc in ips:
            data = _run_async(_ipinfo_lookup(ioc.value, token))
            if data is None:
                errors += 1
                # Mark as enriched to avoid infinite retry loop
                ioc.enriched_at = datetime.now(timezone.utc)
                continue

            cc = data.get("country", "")
            continent_info = _CC_CONTINENT.get(cc, ("", ""))

            ioc.asn = data.get("asn", "")[:20] or None
            ioc.as_name = data.get("as_name", "")[:200] or None
            ioc.as_domain = data.get("as_domain", "")[:200] or None
            ioc.country_code = cc[:5] or None
            ioc.country = (data.get("country_name") or _CC_NAMES.get(cc, ""))[:100] or None
            ioc.continent_code = continent_info[0][:5] or None
            ioc.continent = continent_info[1][:50] or None
            ioc.enriched_at = datetime.now(timezone.utc)

            # Also update the geo array if country not already present
            if ioc.country and ioc.country not in (ioc.geo or []):
                ioc.geo = list(ioc.geo or []) + [ioc.country]

            enriched += 1

        session.commit()
        logger.info("ipinfo_enrichment_complete", enriched=enriched, errors=errors, total=len(ips))
        return {"enriched": enriched, "errors": errors, "total": len(ips)}

    except Exception as e:
        logger.error("ipinfo_enrichment_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


async def _ipinfo_lookup(ip: str, token: str = "") -> dict | None:
    """Call IPinfo API for a single IP. Returns parsed dict or None on error."""
    import httpx

    url = f"{IPINFO_BASE}/{ip}"
    params = {}
    if token:
        params["token"] = token

    try:
        async with httpx.AsyncClient(timeout=IPINFO_TIMEOUT) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 429:
                logger.warning("ipinfo_rate_limited", ip=ip)
                return None
            if resp.status_code != 200:
                logger.debug("ipinfo_http_error", ip=ip, status=resp.status_code)
                return None

            data = resp.json()

            # Parse the "org" field — looks like "AS4766 Korea Telecom"
            org_raw = data.get("org", "")
            asn = ""
            as_name = ""
            if org_raw.startswith("AS"):
                parts = org_raw.split(" ", 1)
                asn = parts[0]
                as_name = parts[1] if len(parts) > 1 else ""

            as_domain = data.get("hostname", "")

            return {
                "ip": data.get("ip", ip),
                "asn": asn,
                "as_name": as_name,
                "as_domain": as_domain,
                "country": data.get("country", ""),  # 2-letter code
                "country_name": _CC_NAMES.get(data.get("country", ""), ""),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "loc": data.get("loc", ""),  # "lat,lng"
            }

    except Exception as e:
        logger.debug("ipinfo_lookup_error", ip=ip, error=str(e))
        return None


# ── Shodan InternetDB IP Enrichment ──────────────────────

INTERNETDB_BASE = "https://internetdb.shodan.io"
INTERNETDB_TIMEOUT = 10


def enrich_ips_internetdb(batch_size: int = 100) -> dict:
    """Batch-enrich IP-type IOCs with open ports, vulns, hostnames from Shodan InternetDB.

    Completely free — no API key needed.
    Picks IPs whose context->'internetdb' is NULL (not yet enriched).
    Stores results in the IOC context JSONB column.
    """
    from sqlalchemy import text as sa_text

    logger.info("internetdb_enrichment_start", batch_size=batch_size)
    session = SyncSession()

    try:
        # Use raw SQL to avoid Postgres enum cast issue with ioc_type
        rows = session.execute(
            sa_text(
                "SELECT id, value FROM iocs "
                "WHERE ioc_type = 'ip' "
                "AND (context->>'internetdb') IS NULL "
                "ORDER BY created_at ASC "
                "LIMIT :lim"
            ),
            {"lim": batch_size},
        ).fetchall()

        if not rows:
            logger.info("internetdb_enrichment_skip", reason="no unenriched IPs")
            return {"enriched": 0, "errors": 0}

        enriched = 0
        errors = 0

        for row in rows:
            ioc_id, ip_value = row[0], row[1]
            data = _run_async(_internetdb_lookup(ip_value))
            if data is None:
                errors += 1
                continue

            # Store the InternetDB result in context JSONB
            import json as _json
            payload = _json.dumps({
                "internetdb": {
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "tags": data.get("tags", []),
                    "enriched_at": datetime.now(timezone.utc).isoformat(),
                }
            })
            session.execute(
                sa_text(
                    "UPDATE iocs SET "
                    "context = COALESCE(context, '{}')::jsonb || :payload::jsonb, "
                    "updated_at = NOW() "
                    "WHERE id = :ioc_id"
                ),
                {"ioc_id": str(ioc_id), "payload": payload},
            )

            # If vulns found, boost risk score
            vulns = data.get("vulns", [])
            if vulns:
                vuln_boost = min(len(vulns) * 5, 30)  # up to +30
                session.execute(
                    sa_text(
                        "UPDATE iocs SET risk_score = LEAST(risk_score + :boost, 100) "
                        "WHERE id = :ioc_id"
                    ),
                    {"boost": vuln_boost, "ioc_id": str(ioc_id)},
                )

            # Add vulns as tags for searchability
            if vulns:
                session.execute(
                    sa_text(
                        "UPDATE iocs SET tags = array_cat(tags, :new_tags) "
                        "WHERE id = :ioc_id"
                    ),
                    {"new_tags": vulns[:10], "ioc_id": str(ioc_id)},
                )

            enriched += 1

        session.commit()
        logger.info("internetdb_enrichment_complete", enriched=enriched, errors=errors, total=len(rows))
        return {"enriched": enriched, "errors": errors, "total": len(rows)}

    except Exception as e:
        logger.error("internetdb_enrichment_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


async def _internetdb_lookup(ip: str) -> dict | None:
    """Query Shodan InternetDB for a single IP."""
    import httpx

    url = f"{INTERNETDB_BASE}/{ip}"
    try:
        async with httpx.AsyncClient(timeout=INTERNETDB_TIMEOUT) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                # IP not in InternetDB — store empty result
                return {"ip": ip, "ports": [], "vulns": [], "hostnames": [], "cpes": [], "tags": []}
            if resp.status_code == 429:
                logger.warning("internetdb_rate_limited", ip=ip)
                return None
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as e:
        logger.debug("internetdb_lookup_error", ip=ip, error=str(e))
        return None


# ── FIRST EPSS Scoring ───────────────────────────────────

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_TIMEOUT = 60


def enrich_epss_scores(batch_size: int = 5000) -> dict:
    """Download FIRST EPSS scores and update CVE-type intel items.

    EPSS (Exploit Prediction Scoring System) provides a probability [0-1] that
    a CVE will be exploited in the next 30 days.  We multiply by 100 and blend
    into the existing risk_score for CVE intel items.

    Free — no API key needed.
    Runs once a day; the CSV is ~250 KB gzipped.
    """
    import csv
    import gzip
    import io

    import httpx
    from sqlalchemy import text as sa_text

    logger.info("epss_enrichment_start")
    session = SyncSession()

    try:
        # 1. Download the EPSS CSV (gzipped)
        resp = _run_async(_download_epss_csv())
        if resp is None:
            return {"error": "Failed to download EPSS CSV"}

        # Parse CSV — first line is a comment, second is header
        reader = csv.DictReader(io.StringIO(resp))
        epss_map: dict[str, float] = {}
        for row in reader:
            cve = row.get("cve", "").strip()
            try:
                score = float(row.get("epss", 0))
            except (ValueError, TypeError):
                score = 0.0
            if cve.startswith("CVE-"):
                epss_map[cve] = score

        logger.info("epss_csv_parsed", total_cves=len(epss_map))

        if not epss_map:
            return {"error": "No EPSS scores found in CSV"}

        # 2. Find intel_items that are CVE-related (have cve_ids)
        #    and update their exploitability_score + risk_score blend
        updated = 0

        # Get CVE items that could benefit from EPSS scoring
        rows = session.execute(
            sa_text(
                "SELECT id, ingested_at, cve_ids, risk_score, exploitability_score "
                "FROM intel_items "
                "WHERE array_length(cve_ids, 1) > 0 "
                "ORDER BY ingested_at DESC "
                "LIMIT :lim"
            ),
            {"lim": batch_size},
        ).fetchall()

        for row in rows:
            item_id, ingested_at, cve_ids, current_risk, current_exploit = (
                row[0], row[1], row[2], row[3], row[4]
            )

            # Find the max EPSS score among this item's CVEs
            max_epss = 0.0
            for cve in (cve_ids or []):
                if cve in epss_map:
                    max_epss = max(max_epss, epss_map[cve])

            if max_epss == 0.0:
                continue

            # Convert EPSS probability to 0-100 scale
            epss_score = round(max_epss * 100, 2)

            # Blend EPSS into risk_score: weighted average (60% existing, 40% EPSS)
            new_risk = min(
                100,
                round(current_risk * 0.6 + epss_score * 0.4),
            )

            session.execute(
                sa_text(
                    "UPDATE intel_items SET "
                    "exploitability_score = :epss, "
                    "risk_score = :risk "
                    "WHERE id = :item_id AND ingested_at = :ts"
                ),
                {
                    "epss": epss_score,
                    "risk": new_risk,
                    "item_id": str(item_id),
                    "ts": ingested_at,
                },
            )
            updated += 1

        # 3. Also update IOCs that are CVE-type
        ioc_rows = session.execute(
            sa_text(
                "SELECT id, value, risk_score FROM iocs "
                "WHERE ioc_type = 'cve' "
                "ORDER BY created_at DESC "
                "LIMIT :lim"
            ),
            {"lim": batch_size},
        ).fetchall()

        ioc_updated = 0
        for row in ioc_rows:
            ioc_id, cve_value, current_risk = row[0], row[1], row[2]
            if cve_value in epss_map:
                epss_prob = epss_map[cve_value]
                epss_score = round(epss_prob * 100, 2)
                new_risk = min(100, round(current_risk * 0.6 + epss_score * 0.4))
                import json as _json
                epss_payload = _json.dumps({
                    "epss": {
                        "score": epss_score,
                        "percentile": round(epss_prob, 6),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                })
                session.execute(
                    sa_text(
                        "UPDATE iocs SET risk_score = :risk, "
                        "context = COALESCE(context, '{}')::jsonb || :payload::jsonb, "
                        "updated_at = NOW() "
                        "WHERE id = :ioc_id"
                    ),
                    {
                        "risk": new_risk,
                        "ioc_id": str(ioc_id),
                        "payload": epss_payload,
                    },
                )
                ioc_updated += 1

        session.commit()
        logger.info(
            "epss_enrichment_complete",
            intel_updated=updated,
            ioc_updated=ioc_updated,
            total_epss_cves=len(epss_map),
        )
        return {
            "intel_updated": updated,
            "ioc_updated": ioc_updated,
            "total_epss_cves": len(epss_map),
        }

    except Exception as e:
        logger.error("epss_enrichment_error", error=str(e))
        session.rollback()
        return {"error": str(e)}
    finally:
        session.close()


async def _download_epss_csv() -> str | None:
    """Download and decompress the EPSS CSV."""
    import gzip

    import httpx

    try:
        async with httpx.AsyncClient(timeout=EPSS_TIMEOUT) as client:
            resp = await client.get(EPSS_CSV_URL)
            if resp.status_code != 200:
                logger.error("epss_download_failed", status=resp.status_code)
                return None
            # Decompress gzip
            raw = gzip.decompress(resp.content).decode("utf-8")

            # The file starts with a comment line starting with '#'
            lines = raw.split("\n")
            data_lines = [l for l in lines if not l.startswith("#")]
            return "\n".join(data_lines)
    except Exception as e:
        logger.error("epss_download_error", error=str(e))
        return None
