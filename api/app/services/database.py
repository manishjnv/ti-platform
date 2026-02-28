"""Database service layer for Intel Items and IOCs."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    AuditLog,
    FeedSyncState,
    IntelIOCLink,
    IntelItem,
    IOC,
    ScoringConfig,
    User,
)
from app.schemas import (
    IntelItemResponse,
    SeverityCount,
)


# ─── Intel Items ──────────────────────────────────────────
async def get_intel_items(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    severity: str | None = None,
    feed_type: str | None = None,
    source_name: str | None = None,
    asset_type: str | None = None,
    sort_by: str = "ingested_at",
    sort_order: str = "desc",
) -> tuple[list[IntelItem], int]:
    """Return paginated intel items with optional filters."""
    query = select(IntelItem)

    if severity:
        query = query.where(IntelItem.severity == text(f"'{severity}'::severity_level"))
    if feed_type:
        query = query.where(IntelItem.feed_type == text(f"'{feed_type}'::feed_type"))
    if source_name:
        query = query.where(IntelItem.source_name == source_name)
    if asset_type:
        query = query.where(IntelItem.asset_type == text(f"'{asset_type}'::asset_type"))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Sort
    col = getattr(IntelItem, sort_by, IntelItem.ingested_at)
    if sort_order == "asc":
        query = query.order_by(col.asc())
    else:
        query = query.order_by(col.desc())

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    return list(result.scalars().all()), total


async def get_intel_item_by_id(db: AsyncSession, item_id: uuid.UUID) -> IntelItem | None:
    result = await db.execute(
        select(IntelItem).where(IntelItem.id == item_id).limit(1)
    )
    return result.scalar_one_or_none()


async def upsert_intel_item(db: AsyncSession, data: dict) -> str:
    """Insert or skip on conflict (source_hash dedup). Returns 'inserted' or 'skipped'."""
    stmt = pg_insert(IntelItem).values(**data)
    stmt = stmt.on_conflict_do_nothing(index_elements=["source_hash"])
    result = await db.execute(stmt)
    return "inserted" if result.rowcount > 0 else "skipped"


async def bulk_upsert_intel_items(db: AsyncSession, items: list[dict]) -> dict:
    """Bulk insert with dedup. Returns counts."""
    if not items:
        return {"inserted": 0, "skipped": 0}

    inserted = 0
    for item in items:
        status = await upsert_intel_item(db, item)
        if status == "inserted":
            inserted += 1

    return {"inserted": inserted, "skipped": len(items) - inserted}


# ─── IOCs ─────────────────────────────────────────────────
async def upsert_ioc(db: AsyncSession, data: dict) -> IOC:
    """Insert or update IOC, incrementing sighting count."""
    stmt = pg_insert(IOC).values(**data)
    stmt = stmt.on_conflict_do_update(
        index_elements=["value", "ioc_type"],
        set_={
            "last_seen": func.now(),
            "sighting_count": IOC.sighting_count + 1,
            "risk_score": stmt.excluded.risk_score,
            "updated_at": func.now(),
        },
    )
    await db.execute(stmt)
    result = await db.execute(
        select(IOC).where(IOC.value == data["value"], IOC.ioc_type == data["ioc_type"])
    )
    return result.scalar_one()


async def get_ioc_by_value(db: AsyncSession, value: str) -> IOC | None:
    result = await db.execute(select(IOC).where(IOC.value == value).limit(1))
    return result.scalar_one_or_none()


async def link_intel_ioc(
    db: AsyncSession,
    intel_id: uuid.UUID,
    intel_ingested_at: datetime,
    ioc_id: uuid.UUID,
    relationship: str = "associated",
) -> None:
    stmt = pg_insert(IntelIOCLink).values(
        intel_id=intel_id,
        intel_ingested_at=intel_ingested_at,
        ioc_id=ioc_id,
        relationship=relationship,
    )
    stmt = stmt.on_conflict_do_nothing()
    await db.execute(stmt)


# ─── Feed Sync State ─────────────────────────────────────
async def get_feed_state(db: AsyncSession, feed_name: str) -> FeedSyncState | None:
    result = await db.execute(
        select(FeedSyncState).where(FeedSyncState.feed_name == feed_name)
    )
    return result.scalar_one_or_none()


async def update_feed_state(
    db: AsyncSession,
    feed_name: str,
    *,
    status: str = "idle",
    last_cursor: str | None = None,
    items_fetched: int = 0,
    items_stored: int = 0,
    error_message: str | None = None,
) -> None:
    state = await get_feed_state(db, feed_name)
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
    state.run_count += 1

    await db.flush()


# ─── Dashboard ────────────────────────────────────────────
async def get_dashboard_stats(db: AsyncSession) -> dict:
    """Aggregate dashboard data."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)

    total = (await db.execute(select(func.count(IntelItem.id)))).scalar() or 0
    last_24h = (
        await db.execute(
            select(func.count(IntelItem.id)).where(IntelItem.ingested_at >= day_ago)
        )
    ).scalar() or 0
    avg_risk = (
        await db.execute(select(func.avg(IntelItem.risk_score)))
    ).scalar() or 0.0
    kev_count = (
        await db.execute(
            select(func.count(IntelItem.id)).where(IntelItem.is_kev.is_(True))
        )
    ).scalar() or 0

    # Severity distribution
    sev_q = (
        select(
            IntelItem.severity,
            IntelItem.feed_type,
            func.count().label("count"),
            func.avg(IntelItem.risk_score).label("avg_risk_score"),
        )
        .where(IntelItem.ingested_at >= now - timedelta(days=30))
        .group_by(IntelItem.severity, IntelItem.feed_type)
    )
    sev_rows = (await db.execute(sev_q)).all()
    severity_distribution = [
        SeverityCount(
            severity=r.severity,
            feed_type=r.feed_type,
            count=r.count,
            avg_risk_score=float(r.avg_risk_score or 0),
        )
        for r in sev_rows
    ]

    # Top risks
    top_q = (
        select(IntelItem)
        .where(IntelItem.risk_score >= 50)
        .order_by(IntelItem.risk_score.desc(), IntelItem.ingested_at.desc())
        .limit(20)
    )
    top_items = (await db.execute(top_q)).scalars().all()

    # Feed statuses
    feeds = (await db.execute(select(FeedSyncState))).scalars().all()

    return {
        "total_items": total,
        "items_last_24h": last_24h,
        "avg_risk_score": round(float(avg_risk), 1),
        "kev_count": kev_count,
        "severity_distribution": severity_distribution,
        "top_risks": top_items,
        "feed_status": feeds,
    }


# ─── Scoring Config ──────────────────────────────────────
async def get_active_scoring_config(db: AsyncSession) -> ScoringConfig | None:
    result = await db.execute(
        select(ScoringConfig).where(ScoringConfig.is_active.is_(True)).limit(1)
    )
    return result.scalar_one_or_none()


# ─── Dashboard Insights ──────────────────────────────────
async def get_dashboard_insights(db: AsyncSession) -> dict:
    """Aggregate threat landscape insights: trending products, threat actors, ransomware, malware."""
    now = datetime.now(timezone.utc)
    periods = {
        "7d": now - timedelta(days=7),
        "30d": now - timedelta(days=30),
        "90d": now - timedelta(days=90),
        "1y": now - timedelta(days=365),
    }

    # ── Trending affected products per time period ────────
    trending_products: dict[str, list[dict]] = {}
    for label, since in periods.items():
        q = text(
            "SELECT p, count(*) AS cnt, "
            "avg(risk_score) AS avg_risk, "
            "bool_or(exploit_available) AS any_exploit "
            "FROM intel_items, unnest(affected_products) AS p "
            "WHERE ingested_at >= :since AND array_length(affected_products, 1) > 0 "
            "GROUP BY p ORDER BY cnt DESC LIMIT 10"
        )
        rows = (await db.execute(q, {"since": since})).all()
        trending_products[label] = [
            {"name": r[0], "count": r[1], "avg_risk": round(float(r[2] or 0), 1), "exploit": bool(r[3])}
            for r in rows
        ]

    # ── Threat actors (from tags containing known patterns) ─
    threat_actor_tags = (
        "apt|threat_actor|lazarus|charming_kitten|cozy_bear|fancy_bear|"
        "turla|sandworm|winnti|hafnium|mustang_panda|kimsuky|"
        "gamaredon|silent_librarian|ocean_lotus|fin7|fin8|cobalt|"
        "ta505|ta551|sidewinder|bitter|donot|transparent_tribe|konni"
    )
    ta_q = text(
        "SELECT t AS tag, count(*) AS cnt, "
        "avg(risk_score) AS avg_risk, "
        "array_agg(DISTINCT unnest_cve) FILTER (WHERE unnest_cve IS NOT NULL) AS cves, "
        "array_agg(DISTINCT unnest_ind) FILTER (WHERE unnest_ind IS NOT NULL) AS industries, "
        "array_agg(DISTINCT unnest_geo) FILTER (WHERE unnest_geo IS NOT NULL) AS regions "
        "FROM intel_items, unnest(tags) AS t "
        "LEFT JOIN LATERAL unnest(cve_ids) AS unnest_cve ON true "
        "LEFT JOIN LATERAL unnest(industries) AS unnest_ind ON true "
        "LEFT JOIN LATERAL unnest(geo) AS unnest_geo ON true "
        "WHERE lower(t) ~ :pattern "
        "GROUP BY t ORDER BY cnt DESC LIMIT 10"
    )
    ta_rows = (await db.execute(ta_q, {"pattern": threat_actor_tags})).all()
    threat_actors = [
        {
            "name": r[0],
            "count": r[1],
            "avg_risk": round(float(r[2] or 0), 1),
            "cves": (r[3] or [])[:8],
            "industries": (r[4] or [])[:6],
            "regions": (r[5] or [])[:6],
        }
        for r in ta_rows
    ]

    # ── Ransomware (tags containing ransomware-related terms) ─
    ransomware_tags = (
        "ransomware|lockbit|blackcat|alphv|clop|royal|"
        "play|medusa|rhysida|akira|bianlian|blackbasta|"
        "conti|ryuk|revil|hive|ragnar|cuba|babuk|"
        "maze|darkside|blackmatter|avoslocker|vice_society"
    )
    rw_q = text(
        "SELECT t AS tag, count(*) AS cnt, "
        "avg(risk_score) AS avg_risk, "
        "bool_or(exploit_available) AS any_exploit, "
        "array_agg(DISTINCT unnest_ind) FILTER (WHERE unnest_ind IS NOT NULL) AS industries, "
        "array_agg(DISTINCT unnest_geo) FILTER (WHERE unnest_geo IS NOT NULL) AS regions "
        "FROM intel_items, unnest(tags) AS t "
        "LEFT JOIN LATERAL unnest(industries) AS unnest_ind ON true "
        "LEFT JOIN LATERAL unnest(geo) AS unnest_geo ON true "
        "WHERE lower(t) ~ :pattern "
        "GROUP BY t ORDER BY cnt DESC LIMIT 10"
    )
    rw_rows = (await db.execute(rw_q, {"pattern": ransomware_tags})).all()
    ransomware = [
        {
            "name": r[0],
            "count": r[1],
            "avg_risk": round(float(r[2] or 0), 1),
            "exploit": bool(r[3]),
            "industries": (r[4] or [])[:6],
            "regions": (r[5] or [])[:6],
        }
        for r in rw_rows
    ]

    # ── Malware families (various malware type tags) ─
    malware_tags = (
        "malware|infostealer|stealer|rootkit|backdoor|"
        "trojan|keylogger|worm|botnet|rat|spyware|"
        "mozi|mirai|smartloader|sshdkit|emotet|"
        "trickbot|qakbot|formbook|agent_tesla|"
        "remcos|asyncrat|redline|raccoon|vidar|"
        "lumma|aurora|stealc|risepro|amadey|"
        "malware_url|malicious_ip|elf|botnetdomain"
    )
    mw_q = text(
        "SELECT t AS tag, count(*) AS cnt, "
        "avg(risk_score) AS avg_risk, "
        "array_agg(DISTINCT unnest_geo) FILTER (WHERE unnest_geo IS NOT NULL) AS regions "
        "FROM intel_items, unnest(tags) AS t "
        "LEFT JOIN LATERAL unnest(geo) AS unnest_geo ON true "
        "WHERE lower(t) ~ :pattern "
        "GROUP BY t ORDER BY cnt DESC LIMIT 15"
    )
    mw_rows = (await db.execute(mw_q, {"pattern": malware_tags})).all()
    malware_families = [
        {
            "name": r[0],
            "count": r[1],
            "avg_risk": round(float(r[2] or 0), 1),
            "regions": (r[3] or [])[:6],
        }
        for r in mw_rows
    ]

    # ── Exploit stats ─
    exploit_count = (
        await db.execute(
            select(func.count(IntelItem.id)).where(IntelItem.exploit_available.is_(True))
        )
    ).scalar() or 0

    return {
        "trending_products": trending_products,
        "threat_actors": threat_actors,
        "ransomware": ransomware,
        "malware_families": malware_families,
        "exploit_count": exploit_count,
    }


# ─── Users ────────────────────────────────────────────────
async def get_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())


async def update_user_role(db: AsyncSession, user_id: uuid.UUID, role: str) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user:
        user.role = role
        await db.flush()
    return user
