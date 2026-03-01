"""Health check endpoint."""

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
    status: str  # ok | degraded
    postgres: bool
    redis: bool
    opensearch: bool
    total_intel: int
    intel_24h: int
    critical_count: int
    high_count: int
    active_feeds: int
    total_feeds: int
    last_feed_at: str | None  # ISO timestamp


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
    ck = cache_key("status_bar")
    cached = await get_cached(ck)
    if cached:
        return cached

    # --- Health checks (same as /health) ---
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

    # --- Quick stats from DB ---
    total_intel = 0
    intel_24h = 0
    critical_count = 0
    high_count = 0
    active_feeds = 0
    total_feeds = 0
    last_feed_at: str | None = None

    try:
        from app.core.database import engine
        from app.models.models import IntelItem, FeedSyncState
        from datetime import timedelta

        async with engine.connect() as conn:
            # Total intel
            total_intel = (await conn.execute(
                select(func.count()).select_from(IntelItem)
            )).scalar() or 0

            # Last 24h
            day_ago = datetime.now(timezone.utc) - timedelta(days=1)
            intel_24h = (await conn.execute(
                select(func.count()).select_from(IntelItem).where(
                    IntelItem.ingested_at >= day_ago
                )
            )).scalar() or 0

            # Critical / high counts
            critical_count = (await conn.execute(
                select(func.count()).select_from(IntelItem).where(
                    IntelItem.severity == "critical"
                )
            )).scalar() or 0
            high_count = (await conn.execute(
                select(func.count()).select_from(IntelItem).where(
                    IntelItem.severity == "high"
                )
            )).scalar() or 0

            # Feed stats
            feeds_rows = (await conn.execute(
                select(
                    func.count().label("total"),
                    func.count().filter(
                        FeedSyncState.status.in_(["success", "running"])
                    ).label("active"),
                    func.max(FeedSyncState.last_success).label("last_success"),
                ).select_from(FeedSyncState)
            )).one()
            total_feeds = feeds_rows.total or 0
            active_feeds = feeds_rows.active or 0
            if feeds_rows.last_success:
                last_feed_at = feeds_rows.last_success.isoformat()
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
    )

    await set_cached(ck, payload.model_dump(), ttl=60)
    return payload
