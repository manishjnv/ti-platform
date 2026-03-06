"""Intelligence Extraction Service.

Extracts structured intelligence (vulnerable products and threat campaigns)
from AI-enriched news items and upserts into dedicated tables.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func, delete, case, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.models import NewsItem, VulnerableProduct, ThreatCampaign

logger = get_logger("intel_extraction")

# ── Windows ──────────────────────────────────────────────
PRODUCTS_WINDOW_HOURS = 48
CAMPAIGNS_WINDOW_DAYS = 7

# Severity priority for merging (higher wins)
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}


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
        for cve in cves:
            cve = cve.strip().upper()
            if not cve.startswith("CVE-"):
                continue

            product_name = products[0] if products else "Unknown Product"
            vendor = _guess_vendor(product_name)

            count += _upsert_product_sync(
                session, item, product_name, vendor, cve, severity
            )
    elif products:
        # No CVEs — just record the products
        for prod in products:
            vendor = _guess_vendor(prod)
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
    campaign = item.campaign_name

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

    stmt = pg_insert(ThreatCampaign).values(
        actor_name=actor_name[:300],
        campaign_name=campaign_name[:300] if campaign_name else None,
        first_seen=item.published_at or now,
        last_seen=item.published_at or now,
        severity=severity,
        targeted_sectors=item.targeted_sectors or [],
        targeted_regions=item.targeted_regions or [],
        malware_used=item.malware_families or [],
        techniques_used=item.tactics_techniques or [],
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

    products_cutoff = now - timedelta(hours=PRODUCTS_WINDOW_HOURS)
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
) -> tuple[list[VulnerableProduct], int]:
    """Fetch vulnerable products within the 48h window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=PRODUCTS_WINDOW_HOURS)

    base = select(VulnerableProduct).where(VulnerableProduct.last_seen >= cutoff)
    count_q = select(func.count(VulnerableProduct.id)).where(VulnerableProduct.last_seen >= cutoff)

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
) -> tuple[list[ThreatCampaign], int]:
    """Fetch threat campaigns within the 7d window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=CAMPAIGNS_WINDOW_DAYS)

    base = select(ThreatCampaign).where(ThreatCampaign.last_seen >= cutoff)
    count_q = select(func.count(ThreatCampaign.id)).where(ThreatCampaign.last_seen >= cutoff)

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


async def get_extraction_stats(db: AsyncSession) -> dict:
    """Get quick stats for the extraction pipeline."""
    now = datetime.now(timezone.utc)
    products_cutoff = now - timedelta(hours=PRODUCTS_WINDOW_HOURS)
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
        "products_window_hours": PRODUCTS_WINDOW_HOURS,
        "campaigns_window_days": CAMPAIGNS_WINDOW_DAYS,
    }


# ──────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────

def _priority_to_severity(priority: str | None) -> str:
    """Map news recommended_priority to severity string."""
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    return mapping.get((priority or "").lower(), "unknown")


def _guess_vendor(product_name: str) -> str | None:
    """Extract vendor from common product naming patterns."""
    known_vendors = {
        "windows": "Microsoft", "office": "Microsoft", "exchange": "Microsoft",
        "azure": "Microsoft", "edge": "Microsoft", ".net": "Microsoft",
        "chrome": "Google", "android": "Google", "chromium": "Google",
        "ios": "Apple", "macos": "Apple", "safari": "Apple", "webkit": "Apple",
        "firefox": "Mozilla", "thunderbird": "Mozilla",
        "linux": "Linux Foundation", "kernel": "Linux Foundation",
        "apache": "Apache", "tomcat": "Apache", "struts": "Apache",
        "nginx": "F5/NGINX", "cisco": "Cisco", "fortinet": "Fortinet",
        "fortigate": "Fortinet", "fortios": "Fortinet",
        "palo alto": "Palo Alto Networks", "pan-os": "Palo Alto Networks",
        "vmware": "VMware/Broadcom", "esxi": "VMware/Broadcom",
        "ivanti": "Ivanti", "pulse": "Ivanti",
        "citrix": "Citrix", "netscaler": "Citrix",
        "confluence": "Atlassian", "jira": "Atlassian",
        "jenkins": "Jenkins", "wordpress": "WordPress",
        "oracle": "Oracle", "java": "Oracle",
        "adobe": "Adobe", "acrobat": "Adobe",
        "sap": "SAP", "ibm": "IBM",
        "juniper": "Juniper Networks", "sonicwall": "SonicWall",
        "zyxel": "Zyxel", "qnap": "QNAP", "synology": "Synology",
        "samsung": "Samsung", "huawei": "Huawei", "tp-link": "TP-Link",
        "d-link": "D-Link",
    }

    name_lower = product_name.lower()
    for keyword, vendor in known_vendors.items():
        if keyword in name_lower:
            return vendor
    return None
