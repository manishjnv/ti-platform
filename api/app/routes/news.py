"""Cyber News endpoints — structured intelligence news feed.

Provides:
  - GET /news — paginated news list with category/tag filtering
  - GET /news/categories — category counts with latest headlines
  - GET /news/{id} — single news item detail
  - POST /news/refresh — trigger manual feed refresh (admin)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings
from app.core.logging import get_logger
from app.middleware.auth import require_viewer
from app.models.models import NewsItem, User
from app.schemas import (
    NewsItemResponse,
    NewsListResponse,
    NewsCategoryCount,
    NewsCategoriesResponse,
)

router = APIRouter(prefix="/news", tags=["news"])
settings = get_settings()
logger = get_logger("news")


@router.get("", response_model=NewsListResponse)
async def list_news(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: str | None = None,
    tag: str | None = None,
    search: str | None = Query(None, max_length=200),
    min_relevance: int | None = Query(None, ge=0, le=100),
    ai_enriched: bool | None = None,
    sort_by: str = Query("published_at", pattern="^(published_at|relevance_score|created_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    """List news items with filtering, pagination, and sorting."""
    ck = cache_key("news_list", page, page_size, category, tag, search, min_relevance, ai_enriched, sort_by, sort_order)
    cached = await get_cached(ck)
    if cached:
        return cached

    # Build query
    base = select(NewsItem)
    count_q = select(func.count(NewsItem.id))

    filters = []
    if category:
        filters.append(NewsItem.category == category)
    if tag:
        filters.append(NewsItem.tags.any(tag))
    if search:
        filters.append(
            or_(
                NewsItem.headline.ilike(f"%{search}%"),
                NewsItem.summary.ilike(f"%{search}%"),
            )
        )
    if min_relevance is not None:
        filters.append(NewsItem.relevance_score >= min_relevance)
    if ai_enriched is not None:
        filters.append(NewsItem.ai_enriched == ai_enriched)

    if filters:
        base = base.where(*filters)
        count_q = count_q.where(*filters)

    # Count
    total_result = await db.execute(count_q)
    total = total_result.scalar() or 0

    # Sort
    sort_col = getattr(NewsItem, sort_by, NewsItem.published_at)
    order = desc(sort_col) if sort_order == "desc" else sort_col.asc()
    # Secondary sort for stability
    base = base.order_by(order, desc(NewsItem.created_at))

    # Paginate
    offset = (page - 1) * page_size
    base = base.offset(offset).limit(page_size)

    result = await db.execute(base)
    items = result.scalars().all()

    pages = max(1, (total + page_size - 1) // page_size)
    response = NewsListResponse(
        items=[NewsItemResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )

    await set_cached(ck, response.model_dump(), ttl=60)
    return response


@router.get("/categories", response_model=NewsCategoriesResponse)
async def news_categories(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get news item counts per category with latest headline."""
    ck = cache_key("news_categories")
    cached = await get_cached(ck)
    if cached:
        return cached

    # Category counts
    count_q = (
        select(
            NewsItem.category,
            func.count(NewsItem.id).label("count"),
        )
        .group_by(NewsItem.category)
    )
    result = await db.execute(count_q)
    rows = result.all()

    categories = []
    for row in rows:
        cat, count = row.category, row.count

        # Get latest headline for this category
        latest_q = (
            select(NewsItem.headline, NewsItem.published_at)
            .where(NewsItem.category == cat)
            .order_by(desc(NewsItem.published_at))
            .limit(1)
        )
        latest_result = await db.execute(latest_q)
        latest = latest_result.first()

        categories.append(NewsCategoryCount(
            category=cat,
            count=count,
            latest_headline=latest.headline if latest else None,
            latest_published_at=latest.published_at if latest else None,
        ))

    # Sort by count descending
    categories.sort(key=lambda c: c.count, reverse=True)

    total_result = await db.execute(select(func.count(NewsItem.id)))
    total = total_result.scalar() or 0

    response = NewsCategoriesResponse(categories=categories, total=total)
    await set_cached(ck, response.model_dump(), ttl=60)
    return response


@router.get("/{news_id}", response_model=NewsItemResponse)
async def get_news_item(
    news_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a single news item by ID."""
    ck = cache_key("news_detail", str(news_id))
    cached = await get_cached(ck)
    if cached:
        return cached

    result = await db.execute(
        select(NewsItem).where(NewsItem.id == news_id)
    )
    item = result.scalar_one_or_none()

    if not item:
        raise HTTPException(status_code=404, detail="News item not found")

    response = NewsItemResponse.model_validate(item)
    await set_cached(ck, response.model_dump(), ttl=120)
    return response


@router.post("/refresh")
async def refresh_news(
    user: Annotated[User, Depends(require_viewer)],
):
    """Trigger manual news feed refresh via worker."""
    from redis import Redis
    from rq import Queue

    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("default", connection=redis_conn)
    job = q.enqueue("worker.tasks.ingest_news")

    logger.info("news_refresh_triggered", job_id=job.id)
    return {"status": "queued", "job_id": job.id}
