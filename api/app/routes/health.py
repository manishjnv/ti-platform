"""Health check & status bar endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text, select, func

from app.core.config import get_settings
from app.core.redis import redis_client, cache_key, get_cached, set_cached
from app.core.opensearch import opensearch_client
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])
settings = get_settings()


class StatusBarResponse(BaseModel):
    # Health
    status: str  # ok | degraded
    postgres: bool
    redis: bool
    opensearch: bool
    # Counts
    total_intel: int
    intel_24h: int
    critical_count: int
    high_count: int
    active_feeds: int
    total_feeds: int
    last_feed_at: str | None
    # New widgets
    avg_risk_score: float
    kev_count: int
    attack_coverage_pct: float
    searches_today: int
    sparkline: list[int]  # 24 hourly bins (oldest → newest)


@router.get("/health", response_model=HealthResponse)
async def health_check():
    pg_ok = False
    redis_ok = False
    os_ok = False

    # PostgreSQL
    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        pg_ok = True
    except Exception:
        pass

    # Redis
    try:
        await redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    # OpenSearch
    try:
        os_ok = opensearch_client.ping()
    except Exception:
        pass

    return HealthResponse(
        status="ok" if (pg_ok and redis_ok) else "degraded",
        version="1.0.0",
        postgres=pg_ok,
        redis=redis_ok,
        opensearch=os_ok,
        environment=settings.environment,
    )


@router.get("/status/bar", response_model=StatusBarResponse)
async def status_bar():
    """Lightweight header status bar — health + quick counts (cached 60s)."""
    ck = cache_key("status_bar_v2")
    cached = await get_cached(ck)
    if cached:
        return cached

    # --- Health checks ---
    pg_ok = redis_ok = os_ok = False
    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        pg_ok = True
    except Exception:
        pass
    try:
        await redis_client.ping()
        redis_ok = True
    except Exception:
        pass
    try:
        os_ok = opensearch_client.ping()
    except Exception:
        pass

    # --- DB stats ---
    total_intel = intel_24h = critical_count = high_count = 0
    active_feeds = total_feeds = kev_count = searches_today = 0
    avg_risk_score = 0.0
    attack_coverage_pct = 0.0
    last_feed_at: str | None = None
    sparkline: list[int] = []

    try:
        from app.core.database import engine
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        async with engine.connect() as conn:
            # Combined counts in one query
            row = (await conn.execute(text(
                "SELECT"
                "  count(*) AS total,"
                "  count(*) FILTER (WHERE ingested_at >= :day_ago) AS last_24h,"
                "  count(*) FILTER (WHERE severity = 'critical') AS crit,"
                "  count(*) FILTER (WHERE severity = 'high') AS high,"
                "  count(*) FILTER (WHERE is_kev) AS kev,"
                "  round(coalesce(avg(risk_score), 0)::numeric, 1) AS avg_risk"
                " FROM intel_items"
            ), {"day_ago": day_ago})).one()
            total_intel = row.total or 0
            intel_24h = row.last_24h or 0
            critical_count = row.crit or 0
            high_count = row.high or 0
            kev_count = row.kev or 0
            avg_risk_score = float(row.avg_risk or 0)

            # Feed stats
            feeds_row = (await conn.execute(text(
                "SELECT count(*) AS total,"
                " count(*) FILTER (WHERE status IN ('success','running')) AS active,"
                " max(last_success) AS last_success"
                " FROM feed_sync_state"
            ))).one()
            total_feeds = feeds_row.total or 0
            active_feeds = feeds_row.active or 0
            if feeds_row.last_success:
                last_feed_at = feeds_row.last_success.isoformat()

            # ATT&CK coverage: parent techniques (non-subtechnique) with at least one intel link
            cov_row = (await conn.execute(text(
                "SELECT"
                "  (SELECT count(DISTINCT id) FROM attack_techniques WHERE is_subtechnique = false) AS total_tech,"
                "  (SELECT count(DISTINCT t.id) FROM attack_techniques t"
                "   JOIN intel_attack_links l ON l.technique_id = t.id"
                "   WHERE t.is_subtechnique = false) AS linked"
            ))).one()
            total_tech = cov_row.total_tech or 1
            linked = cov_row.linked or 0
            attack_coverage_pct = round(linked / max(total_tech, 1) * 100, 1)

            # Searches today (audit_log action = 'search')
            searches_today = (await conn.execute(text(
                "SELECT count(*) FROM audit_log"
                " WHERE action = 'search' AND created_at >= :today"
            ), {"today": now.replace(hour=0, minute=0, second=0, microsecond=0)})).scalar() or 0

            # Sparkline: hourly ingestion count for last 24h
            spark_rows = (await conn.execute(text(
                "WITH hours AS ("
                "  SELECT generate_series("
                "    date_trunc('hour', now() - interval '23 hours'),"
                "    date_trunc('hour', now()),"
                "    interval '1 hour'"
                "  ) AS hr"
                ") SELECT h.hr, coalesce(c.cnt, 0) AS cnt"
                " FROM hours h"
                " LEFT JOIN ("
                "   SELECT date_trunc('hour', ingested_at) AS hr, count(*) AS cnt"
                "   FROM intel_items WHERE ingested_at >= now() - interval '24 hours'"
                "   GROUP BY 1"
                " ) c ON c.hr = h.hr"
                " ORDER BY h.hr"
            ))).all()
            sparkline = [int(r.cnt) for r in spark_rows]
    except Exception:
        pass

    payload = StatusBarResponse(
        status="ok" if (pg_ok and redis_ok) else "degraded",
        postgres=pg_ok,
        redis=redis_ok,
        opensearch=os_ok,
        total_intel=total_intel,
        intel_24h=intel_24h,
        critical_count=critical_count,
        high_count=high_count,
        active_feeds=active_feeds,
        total_feeds=total_feeds,
        last_feed_at=last_feed_at,
        avg_risk_score=avg_risk_score,
        kev_count=kev_count,
        attack_coverage_pct=attack_coverage_pct,
        searches_today=searches_today,
        sparkline=sparkline,
    )

    await set_cached(ck, payload.model_dump(), ttl=60)
    return payload
