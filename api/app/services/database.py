"""Database service layer for Intel Items and IOCs."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select, text
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
    is_kev: bool | None = None,
    exploit_available: bool | None = None,
    search: str | None = None,
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
    if is_kev is not None:
        query = query.where(IntelItem.is_kev == is_kev)
    if exploit_available is not None:
        query = query.where(IntelItem.exploit_available == exploit_available)
    if search:
        query = query.where(
            or_(
                IntelItem.title.ilike(f"%{search}%"),
                IntelItem.summary.ilike(f"%{search}%"),
            )
        )

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
            "WHERE COALESCE(published_at, ingested_at) >= :since AND array_length(affected_products, 1) > 0 "
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
        "ta505|ta551|sidewinder|bitter|donot|transparent_tribe|konni|"
        "dprk|north.korea|luminousmoth|fire.cells|beavertail|"
        "phantomcore|stonefly|uac-0050|espionage|cyber.espionage|"
        "state.sponsor|nation.state"
    )
    ta_q = text(
        "SELECT t AS tag, count(DISTINCT intel_items.id) AS cnt, "
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
        "SELECT t AS tag, count(DISTINCT intel_items.id) AS cnt, "
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
        "malware_url|malicious_ip|elf|botnetdomain|"
        "hajime|clearfake|clickfix|purehvnc|purecrypter|"
        "dohdoor|snakekeylogger|xworm|gootloader|"
        "latrodectus|moonpeak|rekoobe|mimicrat|aisuru|"
        "plugx|valleyrat|nanocore|quasarrat|metasploit|"
        "shellcode|miner|okiru|arechclient|shadowpad|"
        "invisibleferret|ldr4|dcrat|moonrise|webshell"
    )
    mw_q = text(
        "SELECT t AS tag, count(DISTINCT intel_items.id) AS cnt, "
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

    # ── Threat Geography (top targeted regions) ─
    geo_q = text(
        "SELECT g, count(DISTINCT id) AS cnt, "
        "round(avg(risk_score)::numeric, 1) AS avg_risk "
        "FROM intel_items, unnest(geo) AS g "
        "WHERE g IS NOT NULL AND g != '' "
        "GROUP BY g ORDER BY cnt DESC LIMIT 15"
    )
    geo_rows = (await db.execute(geo_q)).all()
    threat_geography = [
        {"name": r[0], "count": r[1], "avg_risk": float(r[2] or 0)}
        for r in geo_rows
    ]

    # ── Target Industries ─
    ind_q = text(
        "SELECT i, count(DISTINCT id) AS cnt, "
        "round(avg(risk_score)::numeric, 1) AS avg_risk "
        "FROM intel_items, unnest(industries) AS i "
        "WHERE i IS NOT NULL AND i != '' "
        "GROUP BY i ORDER BY cnt DESC LIMIT 15"
    )
    ind_rows = (await db.execute(ind_q)).all()
    target_industries = [
        {"name": r[0], "count": r[1], "avg_risk": float(r[2] or 0)}
        for r in ind_rows
    ]

    # ── Attack Techniques (from tags) ─
    attack_technique_tags = (
        "phishing|credential.theft|social.engineering|lateral.movement|"
        "remote.code.execution|data.exfiltration|dll.sideloading|"
        "spear.?phishing|process.hollowing|uacbypass|uac.bypass|"
        "persistence|obfuscation|in-memory|typosquatting|"
        "supply.chain|detection.evasion|dns.abuse|clipboard.access|"
        "credential.stealing|consent.abuse|side.loading|"
        "data.theft|c2.communication|remote.access|api.abuse"
    )
    atk_q = text(
        "SELECT t AS tag, count(DISTINCT intel_items.id) AS cnt "
        "FROM intel_items, unnest(tags) AS t "
        "WHERE lower(t) ~ :pattern "
        "GROUP BY t ORDER BY cnt DESC LIMIT 15"
    )
    atk_rows = (await db.execute(atk_q, {"pattern": attack_technique_tags})).all()
    attack_techniques = [
        {"name": r[0], "count": r[1]}
        for r in atk_rows
    ]

    # ── Ingestion Trend (items per day, last 30 days) ─
    trend_q = text(
        "SELECT DATE(COALESCE(published_at, ingested_at)) AS day, count(*) AS cnt "
        "FROM intel_items "
        "WHERE COALESCE(published_at, ingested_at) >= NOW() - INTERVAL '30 days' "
        "GROUP BY DATE(COALESCE(published_at, ingested_at)) "
        "ORDER BY day"
    )
    trend_rows = (await db.execute(trend_q)).all()
    ingestion_trend = [
        {"date": r[0].isoformat(), "count": r[1]}
        for r in trend_rows
    ]

    # ── EPSS / Exploit Summary Stats ─
    epss_q = text(
        "SELECT "
        "  count(*) FILTER (WHERE exploit_available) AS with_exploit, "
        "  count(*) FILTER (WHERE is_kev) AS kev_count, "
        "  round((avg(exploitability_score) FILTER (WHERE exploitability_score IS NOT NULL))::numeric, 3) AS avg_epss, "
        "  count(*) FILTER (WHERE exploitability_score >= 0.5) AS high_epss_count, "
        "  count(*) AS total "
        "FROM intel_items"
    )
    epss_row = (await db.execute(epss_q)).one()
    exploit_summary = {
        "with_exploit": epss_row[0],
        "kev_count": epss_row[1],
        "avg_epss": float(epss_row[2] or 0),
        "high_epss_count": epss_row[3],
        "total": epss_row[4],
        "exploit_pct": round(epss_row[0] / max(epss_row[4], 1) * 100, 1),
        "kev_pct": round(epss_row[1] / max(epss_row[4], 1) * 100, 1),
    }

    return {
        "trending_products": trending_products,
        "threat_actors": threat_actors,
        "ransomware": ransomware,
        "malware_families": malware_families,
        "exploit_count": exploit_count,
        "threat_geography": threat_geography,
        "target_industries": target_industries,
        "attack_techniques": attack_techniques,
        "ingestion_trend": ingestion_trend,
        "exploit_summary": exploit_summary,
    }


async def get_insight_detail(
    db: AsyncSession,
    *,
    detail_type: str,
    name: str,
    limit: int = 20,
) -> dict:
    """Return detailed information for a dashboard insight entity.

    detail_type: product | threat_actor | ransomware | malware | cve
    name: the entity name / tag / CVE id
    """
    # Build WHERE clause depending on type
    if detail_type == "product":
        where_clause = ":name = ANY(affected_products)"
    elif detail_type in ("threat_actor", "ransomware", "malware"):
        where_clause = ":name = ANY(tags)"
    elif detail_type == "cve":
        where_clause = ":name = ANY(cve_ids)"
    else:
        return {"items": [], "summary": {}}

    # Fetch matching intel items
    items_q = text(
        f"SELECT id, title, summary, severity::text, risk_score, confidence, "
        f"source_name, source_url, feed_type::text, "
        f"tags, geo, industries, cve_ids, affected_products, "
        f"exploit_available, is_kev, published_at, ingested_at, "
        f"related_ioc_count, exploitability_score "
        f"FROM intel_items WHERE {where_clause} "
        f"ORDER BY risk_score DESC, COALESCE(published_at, ingested_at) DESC "
        f"LIMIT :lim"
    )
    rows = (await db.execute(items_q, {"name": name, "lim": limit})).all()

    items = []
    all_cves: list[str] = []
    all_tags: list[str] = []
    all_regions: list[str] = []
    all_industries: list[str] = []
    all_products: list[str] = []
    severity_counts: dict[str, int] = {}
    total_risk = 0.0
    exploit_count = 0

    for r in rows:
        item = {
            "id": str(r[0]),
            "title": r[1],
            "summary": r[2],
            "severity": r[3],
            "risk_score": r[4],
            "confidence": r[5],
            "source_name": r[6],
            "source_url": r[7],
            "feed_type": r[8],
            "tags": r[9] or [],
            "geo": r[10] or [],
            "industries": r[11] or [],
            "cve_ids": r[12] or [],
            "affected_products": r[13] or [],
            "exploit_available": r[14],
            "is_kev": r[15],
            "published_at": r[16].isoformat() if r[16] else None,
            "ingested_at": r[17].isoformat() if r[17] else None,
            "related_ioc_count": r[18],
            "exploitability_score": float(r[19]) if r[19] else None,
        }
        items.append(item)

        # Aggregate
        all_cves.extend(r[12] or [])
        all_tags.extend(r[9] or [])
        all_regions.extend(r[10] or [])
        all_industries.extend(r[11] or [])
        all_products.extend(r[13] or [])
        sev = r[3] or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_risk += float(r[4] or 0)
        if r[14]:
            exploit_count += 1

    # Build summary
    from collections import Counter

    cve_counter = Counter(all_cves)
    tag_counter = Counter(all_tags)
    region_counter = Counter(all_regions)
    industry_counter = Counter(all_industries)
    product_counter = Counter(all_products)

    summary = {
        "total_items": len(items),
        "avg_risk": round(total_risk / max(len(items), 1), 1),
        "exploit_count": exploit_count,
        "severity_distribution": severity_counts,
        "top_cves": [{"name": c, "count": n} for c, n in cve_counter.most_common(10)],
        "top_tags": [{"name": t, "count": n} for t, n in tag_counter.most_common(15)],
        "top_regions": [{"name": r, "count": n} for r, n in region_counter.most_common(10)],
        "top_industries": [{"name": i, "count": n} for i, n in industry_counter.most_common(10)],
        "top_products": [{"name": p, "count": n} for p, n in product_counter.most_common(10)],
    }

    return {"items": items, "summary": summary}


async def get_all_insights_by_type(
    db: AsyncSession,
    *,
    insight_type: str,
    limit: int = 50,
) -> list[dict]:
    """Return all entities for a given insight type (threat_actor, ransomware, malware)."""

    type_patterns = {
        "threat_actor": (
            "apt|threat_actor|lazarus|charming_kitten|cozy_bear|fancy_bear|"
            "turla|sandworm|winnti|hafnium|mustang_panda|kimsuky|"
            "gamaredon|silent_librarian|ocean_lotus|fin7|fin8|cobalt|"
            "ta505|ta551|sidewinder|bitter|donot|transparent_tribe|konni|"
            "dprk|north.korea|luminousmoth|fire.cells|beavertail|"
            "phantomcore|stonefly|uac-0050|espionage|cyber.espionage|"
            "state.sponsor|nation.state"
        ),
        "ransomware": (
            "ransomware|lockbit|blackcat|alphv|clop|royal|"
            "play|medusa|rhysida|akira|bianlian|blackbasta|"
            "conti|ryuk|revil|hive|ragnar|cuba|babuk|"
            "maze|darkside|blackmatter|avoslocker|vice_society"
        ),
        "malware": (
            "malware|infostealer|stealer|rootkit|backdoor|"
            "trojan|keylogger|worm|botnet|rat|spyware|"
            "mozi|mirai|smartloader|sshdkit|emotet|"
            "trickbot|qakbot|formbook|agent_tesla|"
            "remcos|asyncrat|redline|raccoon|vidar|"
            "lumma|aurora|stealc|risepro|amadey|"
            "malware_url|malicious_ip|elf|botnetdomain|"
            "hajime|clearfake|clickfix|purehvnc|purecrypter|"
            "dohdoor|snakekeylogger|xworm|gootloader|"
            "latrodectus|moonpeak|rekoobe|mimicrat|aisuru|"
            "plugx|valleyrat|nanocore|quasarrat|metasploit|"
            "shellcode|miner|okiru|arechclient|shadowpad|"
            "invisibleferret|ldr4|dcrat|moonrise|webshell"
        ),
    }

    pattern = type_patterns.get(insight_type)
    if not pattern:
        return []

    q = text(
        "SELECT t AS tag, count(DISTINCT intel_items.id) AS cnt, "
        "avg(risk_score) AS avg_risk, "
        "array_agg(DISTINCT unnest_cve) FILTER (WHERE unnest_cve IS NOT NULL) AS cves, "
        "array_agg(DISTINCT unnest_ind) FILTER (WHERE unnest_ind IS NOT NULL) AS industries, "
        "array_agg(DISTINCT unnest_geo) FILTER (WHERE unnest_geo IS NOT NULL) AS regions "
        "FROM intel_items, unnest(tags) AS t "
        "LEFT JOIN LATERAL unnest(cve_ids) AS unnest_cve ON true "
        "LEFT JOIN LATERAL unnest(industries) AS unnest_ind ON true "
        "LEFT JOIN LATERAL unnest(geo) AS unnest_geo ON true "
        "WHERE lower(t) ~ :pattern "
        "GROUP BY t ORDER BY cnt DESC LIMIT :lim"
    )
    rows = (await db.execute(q, {"pattern": pattern, "lim": limit})).all()

    return [
        {
            "name": r[0],
            "count": r[1],
            "avg_risk": round(float(r[2] or 0), 1),
            "cves": (r[3] or [])[:10],
            "industries": (r[4] or [])[:8],
            "regions": (r[5] or [])[:8],
        }
        for r in rows
    ]


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
