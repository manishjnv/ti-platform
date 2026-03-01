"""IOC Database endpoints — real queries against the iocs table."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, or_, desc, asc, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.middleware.auth import get_current_user
from app.models.models import User, IOC
from app.services.enrichment import enrich_ioc

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("")
async def list_iocs(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = Query(None, max_length=500),
    ioc_type: str | None = Query(None, max_length=30),
    min_risk: int | None = Query(None, ge=0, le=100),
    max_risk: int | None = Query(None, ge=0, le=100),
    source: str | None = Query(None, max_length=100),
    sort_by: str = Query("last_seen", regex="^(value|ioc_type|risk_score|first_seen|last_seen|sighting_count)$"),
    sort_dir: str = Query("desc", regex="^(asc|desc)$"),
):
    """Paginated, filterable list of real IOCs from the iocs table."""

    base = select(IOC)
    count_q = select(func.count()).select_from(IOC)

    # ── Filters ──────────────────────────────────────────
    if search:
        like = f"%{search}%"
        filt = or_(IOC.value.ilike(like))
        base = base.where(filt)
        count_q = count_q.where(filt)

    if ioc_type:
        base = base.where(IOC.ioc_type == ioc_type)
        count_q = count_q.where(IOC.ioc_type == ioc_type)

    if min_risk is not None:
        base = base.where(IOC.risk_score >= min_risk)
        count_q = count_q.where(IOC.risk_score >= min_risk)

    if max_risk is not None:
        base = base.where(IOC.risk_score <= max_risk)
        count_q = count_q.where(IOC.risk_score <= max_risk)

    if source:
        base = base.where(IOC.source_names.any(source))
        count_q = count_q.where(IOC.source_names.any(source))

    # ── Count ────────────────────────────────────────────
    total = (await db.execute(count_q)).scalar() or 0
    pages = max(1, math.ceil(total / page_size))

    # ── Sort ─────────────────────────────────────────────
    col = getattr(IOC, sort_by)
    base = base.order_by(desc(col) if sort_dir == "desc" else asc(col))

    # ── Paginate ─────────────────────────────────────────
    base = base.offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(base)).scalars().all()

    items = [
        {
            "id": str(r.id),
            "value": r.value,
            "ioc_type": r.ioc_type,
            "risk_score": r.risk_score,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "sighting_count": r.sighting_count,
            "tags": r.tags or [],
            "geo": r.geo or [],
            "source_names": r.source_names or [],
            "context": r.context or {},
        }
        for r in rows
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/stats")
async def ioc_stats(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Aggregate stats for the IOC database page header."""

    total = (await db.execute(select(func.count()).select_from(IOC))).scalar() or 0

    # Type distribution
    type_q = (
        select(IOC.ioc_type, func.count().label("cnt"))
        .group_by(IOC.ioc_type)
        .order_by(desc("cnt"))
    )
    type_rows = (await db.execute(type_q)).all()
    type_dist = [{"name": r.ioc_type, "count": r.cnt} for r in type_rows]

    # Risk distribution (buckets)
    risk_buckets = {
        "critical": (80, 100),
        "high": (60, 79),
        "medium": (40, 59),
        "low": (0, 39),
    }
    risk_dist = {}
    for label, (lo, hi) in risk_buckets.items():
        cnt = (await db.execute(
            select(func.count()).select_from(IOC)
            .where(IOC.risk_score >= lo, IOC.risk_score <= hi)
        )).scalar() or 0
        risk_dist[label] = cnt

    # Source distribution
    src_q = (
        select(func.unnest(IOC.source_names).label("src"), func.count().label("cnt"))
        .group_by("src")
        .order_by(desc("cnt"))
    )
    src_rows = (await db.execute(src_q)).all()
    source_dist = [{"name": r.src, "count": r.cnt} for r in src_rows]

    # Unique sources count
    unique_sources = len(source_dist)

    # ── New enriched stats ───────────────────────────────
    # Average risk score
    avg_risk = (await db.execute(
        select(func.coalesce(func.avg(IOC.risk_score), 0))
    )).scalar() or 0

    # IOCs seen in last 24 hours
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_24h = (await db.execute(
        select(func.count()).select_from(IOC).where(IOC.last_seen >= cutoff_24h)
    )).scalar() or 0

    # Critical + high combined
    high_risk_count = (risk_dist.get("critical", 0) + risk_dist.get("high", 0))

    # Top 5 riskiest IOCs (most recent first when tied)
    top_risky_q = (
        select(IOC)
        .order_by(desc(IOC.risk_score), desc(IOC.last_seen))
        .limit(5)
    )
    top_rows = (await db.execute(top_risky_q)).scalars().all()
    top_risky = [
        {
            "id": str(r.id),
            "value": r.value,
            "ioc_type": r.ioc_type,
            "risk_score": r.risk_score,
            "tags": r.tags or [],
            "source_names": r.source_names or [],
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "sighting_count": r.sighting_count,
        }
        for r in top_rows
    ]

    # Tag distribution (top 15)
    tag_q = (
        select(func.unnest(IOC.tags).label("tag"), func.count().label("cnt"))
        .group_by("tag")
        .order_by(desc("cnt"))
        .limit(15)
    )
    tag_rows = (await db.execute(tag_q)).all()
    tag_dist = [{"name": r.tag, "count": r.cnt} for r in tag_rows]

    # Geo distribution (top 10)
    geo_q = (
        select(func.unnest(IOC.geo).label("g"), func.count().label("cnt"))
        .group_by("g")
        .order_by(desc("cnt"))
        .limit(10)
    )
    geo_rows = (await db.execute(geo_q)).all()
    geo_dist = [{"name": r.g, "count": r.cnt} for r in geo_rows]

    return {
        "total_iocs": total,
        "type_distribution": type_dist,
        "risk_distribution": risk_dist,
        "source_distribution": source_dist,
        "unique_sources": unique_sources,
        "avg_risk_score": round(float(avg_risk), 1),
        "recent_24h": recent_24h,
        "high_risk_count": high_risk_count,
        "top_risky": top_risky,
        "tag_distribution": tag_dist,
        "geo_distribution": geo_dist,
    }


@router.get("/enrich")
async def enrich_ioc_endpoint(
    user: Annotated[User, Depends(get_current_user)],
    value: str = Query(..., max_length=2000),
    ioc_type: str = Query(..., max_length=30),
):
    """On-demand enrichment of a single IOC via VirusTotal + Shodan."""
    result = await enrich_ioc(value, ioc_type)
    return result
