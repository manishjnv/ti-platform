"""Cyber News endpoints — structured intelligence news feed.

Provides:
  - GET /news — paginated news list with category/tag filtering
  - GET /news/categories — category counts with latest headlines
  - GET /news/{id} — single news item detail
  - GET /news/{id}/report — generate downloadable intelligence report
  - POST /news/refresh — trigger manual feed refresh (admin)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
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


# ── Category labels ───────────────────────────────────────
_CAT_LABELS = {
    "active_threats": "Active Threats",
    "exploited_vulnerabilities": "Exploited Vulnerabilities",
    "ransomware_breaches": "Ransomware & Breaches",
    "nation_state": "Nation-State Activity",
    "cloud_identity": "Cloud & Identity",
    "ot_ics": "OT / ICS",
    "security_research": "Security Research",
    "tools_technology": "Tools & Technology",
    "policy_regulation": "Policy & Regulation",
}

_PRIORITY_LABELS = {
    "critical": "CRITICAL — Immediate action required",
    "high": "HIGH — Action within 24 hours",
    "medium": "MEDIUM — Action within 1 week",
    "low": "LOW — Informational / no immediate action",
}


def _build_report_markdown(item: NewsItemResponse) -> str:
    """Generate a structured Markdown intelligence report from a news item."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pub = item.published_at.strftime("%Y-%m-%d %H:%M UTC") if item.published_at else "Unknown"
    cat_label = _CAT_LABELS.get(item.category.value if hasattr(item.category, 'value') else item.category, str(item.category))
    prio = getattr(item, "recommended_priority", "medium") or "medium"
    prio_label = _PRIORITY_LABELS.get(prio, prio)

    lines: list[str] = []
    lines.append(f"# INTELLIGENCE REPORT")
    lines.append("")
    lines.append(f"**Classification:** TLP:GREEN &nbsp;|&nbsp; **Generated:** {now}")
    lines.append(f"**Source:** IntelWatch Cyber News Intelligence")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Header
    lines.append(f"## {item.headline}")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Category** | {cat_label} |")
    lines.append(f"| **Source** | {item.source} |")
    lines.append(f"| **Published** | {pub} |")
    lines.append(f"| **Relevance Score** | {item.relevance_score}/100 |")
    lines.append(f"| **Confidence** | {item.confidence} |")
    lines.append(f"| **Priority** | {prio_label} |")
    if item.campaign_name:
        lines.append(f"| **Campaign** | {item.campaign_name} |")
    if item.initial_access_vector:
        lines.append(f"| **Initial Access** | {item.initial_access_vector} |")
    lines.append("")

    # Executive Summary
    if item.summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(item.summary)
        lines.append("")

    # Executive Brief
    brief = getattr(item, "executive_brief", None)
    if brief:
        lines.append("## Intelligence Brief")
        lines.append("")
        lines.append(brief)
        lines.append("")

    # Risk Assessment
    risk = getattr(item, "risk_assessment", None)
    if risk:
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(risk)
        lines.append("")

    # Attack Narrative
    narrative = getattr(item, "attack_narrative", None)
    if narrative:
        lines.append("## Attack Narrative")
        lines.append("")
        lines.append(narrative)
        lines.append("")

    # Why It Matters
    if item.why_it_matters:
        lines.append("## Key Takeaways")
        lines.append("")
        for pt in item.why_it_matters:
            lines.append(f"- {pt}")
        lines.append("")

    # Threat Landscape
    has_threat_data = item.threat_actors or item.malware_families or item.cves or item.vulnerable_products
    if has_threat_data:
        lines.append("## Threat Landscape")
        lines.append("")
        if item.threat_actors:
            lines.append(f"**Threat Actors:** {', '.join(item.threat_actors)}")
            lines.append("")
        if item.malware_families:
            lines.append(f"**Malware / Tools:** {', '.join(item.malware_families)}")
            lines.append("")
        if item.cves:
            lines.append(f"**CVEs:** {', '.join(item.cves)}")
            lines.append("")
        if item.vulnerable_products:
            lines.append(f"**Affected Products:** {', '.join(item.vulnerable_products)}")
            lines.append("")

    # MITRE ATT&CK
    if item.tactics_techniques:
        lines.append("## MITRE ATT&CK Mapping")
        lines.append("")
        for tt in item.tactics_techniques:
            lines.append(f"- {tt}")
        lines.append("")

    # Post-Exploitation
    if item.post_exploitation:
        lines.append("## Post-Exploitation Activity")
        lines.append("")
        for pe in item.post_exploitation:
            lines.append(f"- {pe}")
        lines.append("")

    # Targeting
    has_targeting = item.targeted_sectors or item.targeted_regions or item.impacted_assets
    if has_targeting:
        lines.append("## Targeting")
        lines.append("")
        if item.targeted_sectors:
            lines.append(f"**Sectors:** {', '.join(item.targeted_sectors)}")
            lines.append("")
        if item.targeted_regions:
            lines.append(f"**Regions:** {', '.join(item.targeted_regions)}")
            lines.append("")
        if item.impacted_assets:
            lines.append(f"**Impacted Assets:** {', '.join(item.impacted_assets)}")
            lines.append("")

    # IOC Summary
    ioc = item.ioc_summary or {}
    has_iocs = any(ioc.get(k) for k in ("domains", "ips", "hashes", "urls"))
    if has_iocs:
        lines.append("## Indicators of Compromise")
        lines.append("")
        lines.append("| Type | Value |")
        lines.append("|---|---|")
        for domain in (ioc.get("domains") or []):
            lines.append(f"| Domain | `{domain}` |")
        for ip in (ioc.get("ips") or []):
            lines.append(f"| IP | `{ip}` |")
        for h in (ioc.get("hashes") or []):
            lines.append(f"| Hash | `{h}` |")
        for url in (ioc.get("urls") or []):
            lines.append(f"| URL | `{url}` |")
        lines.append("")

    # Timeline
    if item.timeline:
        lines.append("## Timeline")
        lines.append("")
        for ev in item.timeline:
            date_str = ev.get("date") or "N/A"
            lines.append(f"- **{date_str}** — {ev.get('event', '')}")
        lines.append("")

    # Detection & Mitigation side-by-side
    if item.detection_opportunities:
        lines.append("## Detection Opportunities")
        lines.append("")
        for det in item.detection_opportunities:
            lines.append(f"- {det}")
        lines.append("")

    if item.mitigation_recommendations:
        lines.append("## Mitigation Recommendations")
        lines.append("")
        for mit in item.mitigation_recommendations:
            lines.append(f"- {mit}")
        lines.append("")

    # Tags
    if item.tags:
        lines.append("---")
        lines.append("")
        lines.append(f"**Tags:** {', '.join(item.tags)}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append(f"*Source URL: {item.source_url}*")
    lines.append("")
    lines.append("*This report was auto-generated by IntelWatch Cyber News Intelligence. AI-enriched analysis may contain inferences based on threat intelligence knowledge.*")

    return "\n".join(lines)


@router.get("/{news_id}/report")
async def generate_news_report(
    news_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("markdown", pattern="^(markdown|text)$"),
):
    """Generate a downloadable intelligence report for a news item."""
    result = await db.execute(
        select(NewsItem).where(NewsItem.id == news_id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="News item not found")

    news_response = NewsItemResponse.model_validate(item)
    report_md = _build_report_markdown(news_response)

    # Sanitize filename
    safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in item.headline[:60]).strip()
    filename = f"IntelWatch-Report-{safe_title}.md"

    return Response(
        content=report_md,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


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
