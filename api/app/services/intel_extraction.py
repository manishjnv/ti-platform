"""Intelligence Extraction Service.

Extracts structured intelligence (vulnerable products and threat campaigns)
from AI-enriched news items and upserts into dedicated tables.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, delete, case, text, cast
from sqlalchemy.dialects.postgresql import insert as pg_insert, ARRAY as PG_ARRAY
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy.types import Text

from app.core.logging import get_logger
from app.models.models import NewsItem, VulnerableProduct, ThreatCampaign
from app.normalizers.entities import (
    is_junk_product as _is_junk_product,
    normalize_product_name as _normalize_product_name,
    normalise_campaign_name as _normalise_campaign_name,
    guess_vendor as _guess_vendor,
)
from app.normalizers.patterns import CVE_RE as _CVE_RE
from app.normalizers.severity import SEVERITY_RANK as _SEVERITY_RANK, priority_to_severity as _priority_to_severity
from app.normalizers.killchain import parse_technique as _parse_technique

logger = get_logger("intel_extraction")

# ── Windows ──────────────────────────────────────────────
PRODUCTS_WINDOW_DAYS = 30
CAMPAIGNS_WINDOW_DAYS = 90


# ──────────────────────────────────────────────────────────
# Sync extraction (called from RQ worker)
# ──────────────────────────────────────────────────────────

def extract_from_news_sync(session: Session, lookback_hours: int = 2) -> dict:
    """Extract intelligence from recently enriched news items (sync version for RQ worker).

    Args:
        session: SQLAlchemy sync Session.
        lookback_hours: Only process items enriched within this window.

    Returns:
        dict with counts of products and campaigns upserted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    # Get recently enriched news items
    result = session.execute(
        select(NewsItem)
        .where(
            NewsItem.ai_enriched.is_(True),
            NewsItem.updated_at >= cutoff,
        )
        .order_by(NewsItem.updated_at.desc())
        .limit(200)
    )
    items = result.scalars().all()

    if not items:
        return {"products_upserted": 0, "campaigns_upserted": 0, "news_processed": 0}

    products_upserted = 0
    campaigns_upserted = 0

    for item in items:
        # ── Extract vulnerable products ──
        products_upserted += _extract_products_sync(session, item)

        # ── Extract threat campaigns ──
        campaigns_upserted += _extract_campaigns_sync(session, item)

    session.commit()

    # ── Deduplicate arrays accumulated from repeated processing ──
    _dedup_arrays_sync(session)

    # ── Prune stale data outside windows ──
    _prune_stale_sync(session)

    logger.info(
        "extraction_complete",
        news_processed=len(items),
        products_upserted=products_upserted,
        campaigns_upserted=campaigns_upserted,
    )

    return {
        "products_upserted": products_upserted,
        "campaigns_upserted": campaigns_upserted,
        "news_processed": len(items),
    }


def _extract_products_sync(session: Session, item: NewsItem) -> int:
    """Extract and upsert vulnerable products from a single news item."""
    count = 0
    products = item.vulnerable_products or []
    cves = item.cves or []

    if not products and not cves:
        return 0

    # Map severity from news priority
    severity = _priority_to_severity(item.recommended_priority)

    # If we have CVEs, create a product entry per CVE
    if cves:
        for raw_cve in cves:
            m = _CVE_RE.search(raw_cve)
            if not m:
                continue
            cve = m.group(1).upper()

            product_name = _normalize_product_name(products[0]) if products else "Unknown Product"
            if _is_junk_product(product_name) and not cve:
                continue
            vendor = _guess_vendor(product_name)

            count += _upsert_product_sync(
                session, item, product_name, vendor, cve, severity
            )
    elif products:
        # No CVEs — skip products that don't meet quality bar
        for prod in products:
            prod = _normalize_product_name(prod)
            if _is_junk_product(prod):
                continue
            vendor = _guess_vendor(prod)
            # Without a CVE, require a recognised vendor
            if vendor is None:
                continue
            count += _upsert_product_sync(
                session, item, prod, vendor, None, severity
            )

    return count


def _upsert_product_sync(
    session: Session,
    item: NewsItem,
    product_name: str,
    vendor: str | None,
    cve_id: str | None,
    severity: str,
) -> int:
    """Upsert a single vulnerable product row."""
    now = datetime.now(timezone.utc)
    news_id = item.id
    new_rank = _SEVERITY_RANK.get(severity, -1)

    # SQL expression: keep the higher severity on conflict
    existing_rank = case(
        (VulnerableProduct.severity == "critical", 4),
        (VulnerableProduct.severity == "high", 3),
        (VulnerableProduct.severity == "medium", 2),
        (VulnerableProduct.severity == "low", 1),
        (VulnerableProduct.severity == "info", 0),
        else_=-1,
    )

    stmt = pg_insert(VulnerableProduct).values(
        product_name=product_name[:300],
        vendor=vendor[:200] if vendor else None,
        cve_id=cve_id,
        severity=severity,
        is_kev=False,
        targeted_sectors=item.targeted_sectors or [],
        targeted_regions=item.targeted_regions or [],
        source_count=1,
        source_news_ids=[news_id],
        first_seen=item.published_at or now,
        last_seen=item.published_at or now,
        confidence=item.confidence if item.confidence in ("high", "medium", "low") else "medium",
    ).on_conflict_do_update(
        constraint="uq_ivp_product_cve",
        set_={
            "severity": case(
                (existing_rank >= new_rank, VulnerableProduct.severity),
                else_=severity,
            ),
            "last_seen": func.greatest(VulnerableProduct.last_seen, item.published_at or now),
            "source_count": VulnerableProduct.source_count + 1,
            "source_news_ids": func.array_append(VulnerableProduct.source_news_ids, news_id),
            "targeted_sectors": func.array_cat(VulnerableProduct.targeted_sectors, item.targeted_sectors or []),
            "targeted_regions": func.array_cat(VulnerableProduct.targeted_regions, item.targeted_regions or []),
            "updated_at": now,
        },
    )

    try:
        session.execute(stmt)
        return 1
    except Exception as e:
        logger.warning("product_upsert_error", product=product_name, cve=cve_id, error=str(e))
        session.rollback()
        return 0


def _extract_campaigns_sync(session: Session, item: NewsItem) -> int:
    """Extract and upsert threat campaigns from a single news item."""
    count = 0
    actors = item.threat_actors or []

    if not actors:
        return 0

    severity = _priority_to_severity(item.recommended_priority)
    campaign = _normalise_campaign_name(item.campaign_name)

    for actor in actors:
        actor = actor.strip()
        if not actor or actor.lower() in ("unknown", "unattributed", "n/a", "none"):
            continue

        count += _upsert_campaign_sync(session, item, actor, campaign, severity)

    return count


def _upsert_campaign_sync(
    session: Session,
    item: NewsItem,
    actor_name: str,
    campaign_name: str | None,
    severity: str,
) -> int:
    """Upsert a single threat campaign row."""
    now = datetime.now(timezone.utc)
    news_id = item.id
    new_rank = _SEVERITY_RANK.get(severity, -1)

    existing_rank = case(
        (ThreatCampaign.severity == "critical", 4),
        (ThreatCampaign.severity == "high", 3),
        (ThreatCampaign.severity == "medium", 2),
        (ThreatCampaign.severity == "low", 1),
        (ThreatCampaign.severity == "info", 0),
        else_=-1,
    )

    # Normalise technique IDs: "T1566.001 - Phishing" → "T1566.001"
    raw_techniques = item.tactics_techniques or []
    normalised_techniques = []
    for t in raw_techniques:
        tid, _ = _parse_technique(str(t))
        normalised_techniques.append(tid if tid else str(t))

    stmt = pg_insert(ThreatCampaign).values(
        actor_name=actor_name[:300],
        campaign_name=campaign_name[:300] if campaign_name else None,
        first_seen=item.published_at or now,
        last_seen=item.published_at or now,
        severity=severity,
        targeted_sectors=item.targeted_sectors or [],
        targeted_regions=item.targeted_regions or [],
        malware_used=item.malware_families or [],
        techniques_used=normalised_techniques,
        cves_exploited=item.cves or [],
        source_count=1,
        source_news_ids=[news_id],
        confidence=item.confidence if item.confidence in ("high", "medium", "low") else "medium",
    ).on_conflict_do_update(
        constraint="uq_itc_actor_campaign",
        set_={
            "severity": case(
                (existing_rank >= new_rank, ThreatCampaign.severity),
                else_=severity,
            ),
            "last_seen": func.greatest(ThreatCampaign.last_seen, item.published_at or now),
            "source_count": ThreatCampaign.source_count + 1,
            "source_news_ids": func.array_append(ThreatCampaign.source_news_ids, news_id),
            "targeted_sectors": func.array_cat(ThreatCampaign.targeted_sectors, item.targeted_sectors or []),
            "targeted_regions": func.array_cat(ThreatCampaign.targeted_regions, item.targeted_regions or []),
            "malware_used": func.array_cat(ThreatCampaign.malware_used, item.malware_families or []),
            "techniques_used": func.array_cat(ThreatCampaign.techniques_used, item.tactics_techniques or []),
            "cves_exploited": func.array_cat(ThreatCampaign.cves_exploited, item.cves or []),
            "updated_at": now,
        },
    )

    try:
        session.execute(stmt)
        return 1
    except Exception as e:
        logger.warning("campaign_upsert_error", actor=actor_name, campaign=campaign_name, error=str(e))
        session.rollback()
        return 0


def _prune_stale_sync(session: Session) -> None:
    """Remove entries older than their respective windows."""
    now = datetime.now(timezone.utc)

    products_cutoff = now - timedelta(days=PRODUCTS_WINDOW_DAYS)
    campaigns_cutoff = now - timedelta(days=CAMPAIGNS_WINDOW_DAYS)

    try:
        r1 = session.execute(
            delete(VulnerableProduct).where(VulnerableProduct.last_seen < products_cutoff)
        )
        r2 = session.execute(
            delete(ThreatCampaign).where(ThreatCampaign.last_seen < campaigns_cutoff)
        )
        session.commit()
        pruned_products = r1.rowcount or 0
        pruned_campaigns = r2.rowcount or 0
        if pruned_products or pruned_campaigns:
            logger.info("extraction_prune", pruned_products=pruned_products, pruned_campaigns=pruned_campaigns)
    except Exception as e:
        logger.warning("extraction_prune_error", error=str(e))
        session.rollback()


def _dedup_arrays_sync(session: Session) -> None:
    """Deduplicate array columns and recalculate source_count after batch upserts."""
    try:
        session.execute(text("""
            UPDATE intel_vulnerable_products SET
                targeted_sectors = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(targeted_sectors) v), '{}'),
                targeted_regions = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(targeted_regions) v), '{}'),
                source_news_ids = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(source_news_ids) v), '{}'),
                source_count = COALESCE(array_length(
                    (SELECT array_agg(DISTINCT v) FROM unnest(source_news_ids) v), 1
                ), 1)
            WHERE updated_at >= NOW() - INTERVAL '3 hours'
        """))
        session.execute(text("""
            UPDATE intel_threat_campaigns SET
                targeted_sectors = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(targeted_sectors) v), '{}'),
                targeted_regions = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(targeted_regions) v), '{}'),
                malware_used = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(malware_used) v), '{}'),
                techniques_used = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(techniques_used) v), '{}'),
                cves_exploited = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(cves_exploited) v), '{}'),
                source_news_ids = COALESCE((SELECT array_agg(DISTINCT v) FROM unnest(source_news_ids) v), '{}'),
                source_count = COALESCE(array_length(
                    (SELECT array_agg(DISTINCT v) FROM unnest(source_news_ids) v), 1
                ), 1)
            WHERE updated_at >= NOW() - INTERVAL '8 days'
        """))
        session.commit()
    except Exception as e:
        logger.warning("extraction_dedup_error", error=str(e))
        session.rollback()


# ──────────────────────────────────────────────────────────
# Async queries (called from API endpoints)
# ──────────────────────────────────────────────────────────

async def get_vulnerable_products(
    db: AsyncSession,
    *,
    search: str | None = None,
    severity: str | None = None,
    sort_by: str = "last_seen",
    sort_order: str = "desc",
    limit: int = 100,
    window_hours: int | None = 24,
) -> tuple[list[VulnerableProduct], int]:
    """Fetch vulnerable products within the rolling window."""
    base = select(VulnerableProduct)
    count_q = select(func.count(VulnerableProduct.id))

    if window_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        base = base.where(VulnerableProduct.last_seen >= cutoff)
        count_q = count_q.where(VulnerableProduct.last_seen >= cutoff)

    if search:
        like = f"%{search}%"
        base = base.where(
            VulnerableProduct.product_name.ilike(like)
            | VulnerableProduct.cve_id.ilike(like)
            | VulnerableProduct.vendor.ilike(like)
        )
        count_q = count_q.where(
            VulnerableProduct.product_name.ilike(like)
            | VulnerableProduct.cve_id.ilike(like)
            | VulnerableProduct.vendor.ilike(like)
        )

    if severity:
        base = base.where(VulnerableProduct.severity == severity)
        count_q = count_q.where(VulnerableProduct.severity == severity)

    # Sort
    valid_sorts = {"last_seen", "cvss_score", "epss_score", "severity", "source_count", "product_name"}
    col_name = sort_by if sort_by in valid_sorts else "last_seen"
    col = getattr(VulnerableProduct, col_name, VulnerableProduct.last_seen)
    order = col.desc() if sort_order == "desc" else col.asc()
    base = base.order_by(order).limit(limit)

    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    result = await db.execute(base)
    items = result.scalars().all()

    return items, total


async def get_threat_campaigns(
    db: AsyncSession,
    *,
    search: str | None = None,
    severity: str | None = None,
    sort_by: str = "last_seen",
    sort_order: str = "desc",
    limit: int = 100,
    window_days: int | None = 7,
) -> tuple[list[ThreatCampaign], int]:
    """Fetch threat campaigns within the rolling window."""
    base = select(ThreatCampaign)
    count_q = select(func.count(ThreatCampaign.id))

    if window_days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        base = base.where(ThreatCampaign.last_seen >= cutoff)
        count_q = count_q.where(ThreatCampaign.last_seen >= cutoff)

    if search:
        like = f"%{search}%"
        base = base.where(
            ThreatCampaign.actor_name.ilike(like)
            | ThreatCampaign.campaign_name.ilike(like)
        )
        count_q = count_q.where(
            ThreatCampaign.actor_name.ilike(like)
            | ThreatCampaign.campaign_name.ilike(like)
        )

    if severity:
        base = base.where(ThreatCampaign.severity == severity)
        count_q = count_q.where(ThreatCampaign.severity == severity)

    # Sort
    valid_sorts = {"last_seen", "severity", "source_count", "actor_name"}
    col_name = sort_by if sort_by in valid_sorts else "last_seen"
    col = getattr(ThreatCampaign, col_name, ThreatCampaign.last_seen)
    order = col.desc() if sort_order == "desc" else col.asc()
    base = base.order_by(order).limit(limit)

    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    result = await db.execute(base)
    items = result.scalars().all()

    return items, total


async def resolve_product_campaign_links(
    db: AsyncSession,
    products: list[VulnerableProduct],
) -> dict[str, list[dict]]:
    """For each product with a CVE, find ThreatCampaigns that exploit the same CVE.

    Returns a dict keyed by product.id → list of brief campaign dicts.
    """
    cve_to_product_ids: dict[str, list] = {}
    for p in products:
        if p.cve_id:
            cve_to_product_ids.setdefault(p.cve_id, []).append(p.id)

    if not cve_to_product_ids:
        return {}

    # Find campaigns that have ANY of these CVEs in cves_exploited
    # Use raw SQL && (overlap) operator since ORM .overlap() isn't available for all Mapped ARRAY columns
    all_cves = list(cve_to_product_ids.keys())
    result = await db.execute(
        select(
            ThreatCampaign.id,
            ThreatCampaign.actor_name,
            ThreatCampaign.campaign_name,
            ThreatCampaign.severity,
            ThreatCampaign.cves_exploited,
        ).where(
            ThreatCampaign.cves_exploited.bool_op("&&")(cast(all_cves, PG_ARRAY(Text)))
        )
    )
    campaigns = result.all()

    # Build product_id → [campaign briefs]
    links: dict[str, list[dict]] = {}
    for c in campaigns:
        brief = {
            "id": str(c.id),
            "actor_name": c.actor_name,
            "campaign_name": c.campaign_name,
            "severity": c.severity,
        }
        for cve in (c.cves_exploited or []):
            for pid in cve_to_product_ids.get(cve, []):
                links.setdefault(str(pid), []).append(brief)

    # Deduplicate by campaign id
    for pid in links:
        seen = set()
        deduped = []
        for b in links[pid]:
            if b["id"] not in seen:
                seen.add(b["id"])
                deduped.append(b)
        links[pid] = deduped

    return links


async def resolve_campaign_product_links(
    db: AsyncSession,
    campaigns: list[ThreatCampaign],
) -> dict[str, list[dict]]:
    """For each campaign, find VulnerableProducts whose CVE appears in cves_exploited.

    Returns a dict keyed by campaign.id → list of brief product dicts.
    """
    all_cves: set[str] = set()
    campaign_cves: dict[str, list[str]] = {}
    for c in campaigns:
        cves = c.cves_exploited or []
        if cves:
            campaign_cves[str(c.id)] = cves
            all_cves.update(cves)

    if not all_cves:
        return {}

    result = await db.execute(
        select(
            VulnerableProduct.id,
            VulnerableProduct.product_name,
            VulnerableProduct.vendor,
            VulnerableProduct.cve_id,
            VulnerableProduct.cvss_score,
            VulnerableProduct.severity,
        ).where(VulnerableProduct.cve_id.in_(all_cves))
    )
    products = result.all()

    # Index products by CVE
    cve_to_products: dict[str, list[dict]] = {}
    for p in products:
        brief = {
            "id": str(p.id),
            "product_name": p.product_name,
            "vendor": p.vendor,
            "cve_id": p.cve_id,
            "cvss_score": p.cvss_score,
            "severity": p.severity,
        }
        cve_to_products.setdefault(p.cve_id, []).append(brief)

    # Build campaign_id → [product briefs]
    links: dict[str, list[dict]] = {}
    for cid, cves in campaign_cves.items():
        seen = set()
        for cve in cves:
            for brief in cve_to_products.get(cve, []):
                if brief["id"] not in seen:
                    seen.add(brief["id"])
                    links.setdefault(cid, []).append(brief)

    return links


async def get_extraction_stats(db: AsyncSession) -> dict:
    """Get quick stats for the extraction pipeline."""
    now = datetime.now(timezone.utc)
    products_cutoff = now - timedelta(days=PRODUCTS_WINDOW_DAYS)
    campaigns_cutoff = now - timedelta(days=CAMPAIGNS_WINDOW_DAYS)

    p_count = await db.execute(
        select(func.count(VulnerableProduct.id)).where(VulnerableProduct.last_seen >= products_cutoff)
    )
    c_count = await db.execute(
        select(func.count(ThreatCampaign.id)).where(ThreatCampaign.last_seen >= campaigns_cutoff)
    )

    # Last extraction time = most recent updated_at across both tables
    p_latest = await db.execute(
        select(func.max(VulnerableProduct.updated_at))
    )
    c_latest = await db.execute(
        select(func.max(ThreatCampaign.updated_at))
    )

    p_time = p_latest.scalar()
    c_time = c_latest.scalar()
    last_at = max(filter(None, [p_time, c_time]), default=None)

    return {
        "vulnerable_products_count": p_count.scalar() or 0,
        "threat_campaigns_count": c_count.scalar() or 0,
        "last_extraction_at": last_at,
        "products_window_days": PRODUCTS_WINDOW_DAYS,
        "campaigns_window_days": CAMPAIGNS_WINDOW_DAYS,
    }


async def get_vendor_stats(db: AsyncSession, *, limit: int = 15) -> list[dict]:
    """Top vendors by product count with severity breakdown."""
    result = await db.execute(
        select(
            VulnerableProduct.vendor,
            func.count(VulnerableProduct.id).label("count"),
            func.count(VulnerableProduct.id).filter(VulnerableProduct.severity == "critical").label("critical"),
            func.count(VulnerableProduct.id).filter(VulnerableProduct.severity == "high").label("high"),
            func.count(VulnerableProduct.id).filter(VulnerableProduct.is_kev.is_(True)).label("kev_count"),
        )
        .where(VulnerableProduct.vendor.isnot(None))
        .group_by(VulnerableProduct.vendor)
        .order_by(func.count(VulnerableProduct.id).desc())
        .limit(limit)
    )
    return [
        {
            "vendor": row.vendor,
            "count": row.count,
            "critical": row.critical,
            "high": row.high,
            "kev_count": row.kev_count,
        }
        for row in result.all()
    ]
