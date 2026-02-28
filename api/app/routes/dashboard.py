"""Dashboard endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings
from app.middleware.auth import require_viewer
from app.models.models import User
from app.schemas import DashboardResponse, IntelItemResponse, FeedStatusResponse
from app.services import database as db_service

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
settings = get_settings()


@router.get("", response_model=DashboardResponse)
async def get_dashboard(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get dashboard data with caching."""
    ck = cache_key("dashboard")
    cached = await get_cached(ck)
    if cached:
        return cached

    stats = await db_service.get_dashboard_stats(db)

    response = DashboardResponse(
        severity_distribution=stats["severity_distribution"],
        top_risks=[IntelItemResponse.model_validate(i) for i in stats["top_risks"]],
        total_items=stats["total_items"],
        items_last_24h=stats["items_last_24h"],
        avg_risk_score=stats["avg_risk_score"],
        kev_count=stats["kev_count"],
        feed_status=[FeedStatusResponse.model_validate(f) for f in stats["feed_status"]],
    )

    await set_cached(ck, response.model_dump(), ttl=settings.cache_ttl_dashboard)
    return response


@router.get("/insights")
async def get_dashboard_insights(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get threat landscape insights: trending products, threat actors, ransomware, malware."""
    ck = cache_key("dashboard_insights")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = await db_service.get_dashboard_insights(db)
    await set_cached(ck, data, ttl=300)  # cache 5 min
    return data


@router.get("/insights/detail")
async def get_insight_detail(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    type: str = Query(..., description="Entity type: product|threat_actor|ransomware|malware|cve"),
    name: str = Query(..., description="Entity name / tag / CVE ID"),
):
    """Return detailed intel items and aggregated summary for a specific dashboard insight entity."""
    ck = cache_key(f"insight_detail:{type}:{name}")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = await db_service.get_insight_detail(db, detail_type=type, name=name, limit=30)
    await set_cached(ck, data, ttl=300)
    return data


@router.get("/insights/all")
async def get_all_insights(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    type: str = Query(..., description="Insight type: threat_actor|ransomware|malware"),
):
    """Return all entities for a given insight type (up to 50)."""
    ck = cache_key(f"insight_all:{type}")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = await db_service.get_all_insights_by_type(db, insight_type=type, limit=50)
    await set_cached(ck, data, ttl=300)
    return data
