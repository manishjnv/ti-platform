"""Cyber News endpoints — structured intelligence news feed.

Provides:
  - GET /news — paginated news list with category/tag filtering
  - GET /news/categories — category counts with latest headlines
  - GET /news/{id} — single news item detail
  - GET /news/{id}/report — generate downloadable report (pdf|html|markdown)
  - POST /news/refresh — trigger manual feed refresh (admin)
"""

from __future__ import annotations

import io
import re
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
from app.middleware.auth import require_viewer, require_analyst
from app.models.models import NewsItem, User, VulnerableProduct, ThreatCampaign
from app.schemas import (
    NewsItemResponse,
    NewsListResponse,
    NewsCategoryCount,
    NewsCategoriesResponse,
    NewsFeedStatusResponse,
    NewsPipelineStatusResponse,
    NewsStatsResponse,
    SourceArticle,
    VulnerableProductResponse,
    VulnerableProductsListResponse,
    ThreatCampaignResponse,
    ThreatCampaignsListResponse,
    ExtractionStatsResponse,
)

router = APIRouter(prefix="/news", tags=["news"])
settings = get_settings()
logger = get_logger("news")


@router.get("/feed-status", response_model=list[NewsFeedStatusResponse])
async def news_feed_status(
    user: Annotated[User, Depends(require_viewer)],
):
    """Get fetch health status of all news RSS feed sources."""
    from app.services.news import get_news_feed_statuses, NEWS_FEEDS

    statuses = await get_news_feed_statuses()
    status_map = {s.source_name: s for s in statuses}

    # Return all configured feeds — even those without a DB row yet
    result = []
    for feed in NEWS_FEEDS:
        name = feed["name"]
        if name in status_map:
            result.append(NewsFeedStatusResponse.model_validate(status_map[name]))
        else:
            result.append(NewsFeedStatusResponse(
                source_name=name,
                source_url=feed["url"],
                status="unknown",
            ))
    return result


@router.get("/pipeline-status", response_model=NewsPipelineStatusResponse)
async def news_pipeline_status(
    user: Annotated[User, Depends(require_viewer)],
):
    """Get overall health of the news ingestion pipeline.

    Returns stale=true if no new articles were stored in the last hour.
    """
    from app.services.news import get_news_pipeline_status

    data = await get_news_pipeline_status()
    return NewsPipelineStatusResponse(**data)


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


@router.get("/stats", response_model=NewsStatsResponse)
async def news_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Global stats across ALL articles — used by the QuickStatsBar."""
    from datetime import timedelta

    ck = cache_key("news_stats")
    cached = await get_cached(ck)
    if cached:
        return cached

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Single query for all scalar stats
    q = select(
        func.count(NewsItem.id).label("total"),
        func.count(NewsItem.id).filter(NewsItem.published_at >= today_start).label("today"),
        func.count(NewsItem.id).filter(NewsItem.relevance_score >= 80).label("critical"),
        func.count(NewsItem.id).filter(
            NewsItem.recommended_priority.in_(["critical", "high"])
        ).label("high"),
        func.coalesce(func.round(func.avg(NewsItem.relevance_score)), 0).label("avg_score"),
        func.count(func.distinct(NewsItem.source)).label("sources"),
        func.count(NewsItem.id).filter(NewsItem.ai_enriched == True).label("enriched"),
    )
    row = (await db.execute(q)).one()

    total = row.total or 0
    enriched_pct = round(100 * row.enriched / total) if total else 0

    response = NewsStatsResponse(
        total=total,
        today=row.today or 0,
        critical=row.critical or 0,
        high=row.high or 0,
        avg_score=int(row.avg_score or 0),
        sources=row.sources or 0,
        enriched_pct=enriched_pct,
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

    # Category counts — only enriched items (matches default UI filter)
    count_q = (
        select(
            NewsItem.category,
            func.count(NewsItem.id).label("count"),
        )
        .where(NewsItem.ai_enriched == True)
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
            .where(NewsItem.category == cat, NewsItem.ai_enriched == True)
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

    total_result = await db.execute(select(func.count(NewsItem.id)).where(NewsItem.ai_enriched == True))
    total = total_result.scalar() or 0

    response = NewsCategoriesResponse(categories=categories, total=total)
    await set_cached(ck, response.model_dump(), ttl=60)
    return response


# ── Intelligence Extraction Endpoints ──────────────────────

@router.get("/vulnerable-products", response_model=VulnerableProductsListResponse)
async def list_vulnerable_products(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info|unknown)$"),
    sort_by: str = Query("last_seen", pattern="^(last_seen|cvss_score|epss_score|severity|source_count|product_name)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(100, ge=1, le=500),
    window: str = Query("24h", pattern="^(24h|all)$"),
):
    """Get vulnerable products extracted from news."""
    from app.services.intel_extraction import get_vulnerable_products, PRODUCTS_WINDOW_DAYS, resolve_product_campaign_links

    window_hours = 24 if window == "24h" else None

    ck = cache_key("vuln_products", search, severity, sort_by, sort_order, limit, window)
    cached = await get_cached(ck)
    if cached:
        return cached

    items, total = await get_vulnerable_products(
        db, search=search, severity=severity, sort_by=sort_by, sort_order=sort_order,
        limit=limit, window_hours=window_hours,
    )

    # Resolve source articles
    all_ids = set()
    for i in items:
        all_ids.update(i.source_news_ids or [])
    source_map = await _resolve_source_articles(db, all_ids)

    # Resolve cross-links (products → campaigns via shared CVEs)
    campaign_links = await resolve_product_campaign_links(db, items)

    resp_items = []
    for i in items:
        obj = VulnerableProductResponse.model_validate(i)
        obj.source_articles = [source_map[sid] for sid in (i.source_news_ids or []) if sid in source_map]
        obj.related_campaigns = campaign_links.get(str(i.id), [])
        resp_items.append(obj)

    response = VulnerableProductsListResponse(
        items=resp_items,
        total=total,
        window_days=PRODUCTS_WINDOW_DAYS,
    )
    await set_cached(ck, response.model_dump(), ttl=60)
    return response


@router.get("/threat-campaigns", response_model=ThreatCampaignsListResponse)
async def list_threat_campaigns(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: str | None = Query(None, max_length=200),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low|info|unknown)$"),
    sort_by: str = Query("last_seen", pattern="^(last_seen|severity|source_count|actor_name)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(100, ge=1, le=500),
    window: str = Query("7d", pattern="^(7d|all)$"),
):
    """Get active threat actors & campaigns from news."""
    from app.services.intel_extraction import get_threat_campaigns, CAMPAIGNS_WINDOW_DAYS, resolve_campaign_product_links

    window_days = 7 if window == "7d" else None

    ck = cache_key("threat_campaigns", search, severity, sort_by, sort_order, limit, window)
    cached = await get_cached(ck)
    if cached:
        return cached

    items, total = await get_threat_campaigns(
        db, search=search, severity=severity, sort_by=sort_by, sort_order=sort_order,
        limit=limit, window_days=window_days,
    )

    # Resolve source articles
    all_ids = set()
    for i in items:
        all_ids.update(i.source_news_ids or [])
    source_map = await _resolve_source_articles(db, all_ids)

    # Resolve cross-links (campaigns → products via shared CVEs)
    product_links = await resolve_campaign_product_links(db, items)

    resp_items = []
    for i in items:
        obj = ThreatCampaignResponse.model_validate(i)
        obj.source_articles = [source_map[sid] for sid in (i.source_news_ids or []) if sid in source_map]
        obj.related_products = product_links.get(str(i.id), [])
        resp_items.append(obj)

    response = ThreatCampaignsListResponse(
        items=resp_items,
        total=total,
        window_days=CAMPAIGNS_WINDOW_DAYS,
    )
    await set_cached(ck, response.model_dump(), ttl=60)
    return response


async def _resolve_source_articles(db: AsyncSession, news_ids: set) -> dict:
    """Bulk-fetch NewsItem headline/source/source_url/published_at for a set of IDs."""
    if not news_ids:
        return {}
    result = await db.execute(
        select(
            NewsItem.id, NewsItem.headline, NewsItem.source,
            NewsItem.source_url, NewsItem.published_at,
        ).where(NewsItem.id.in_(news_ids))
    )
    return {
        row.id: SourceArticle(
            id=row.id,
            headline=row.headline,
            source=row.source,
            source_url=row.source_url,
            published_at=row.published_at,
        )
        for row in result.all()
    }


@router.get("/extraction-stats", response_model=ExtractionStatsResponse)
async def extraction_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get intelligence extraction pipeline statistics."""
    from app.services.intel_extraction import get_extraction_stats

    ck = cache_key("extraction_stats")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = await get_extraction_stats(db)
    response = ExtractionStatsResponse(**data)
    await set_cached(ck, response.model_dump(), ttl=30)
    return response


@router.get("/vulnerable-products/export")
async def export_vulnerable_products(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("csv", pattern="^(csv|json)$"),
    window: str = Query("all", pattern="^(24h|all)$"),
):
    """Export vulnerable products as CSV or JSON."""
    from app.services.intel_extraction import get_vulnerable_products

    window_hours = 24 if window == "24h" else None
    items, _ = await get_vulnerable_products(db, limit=5000, window_hours=window_hours)

    if format == "json":
        import json
        rows = [
            {
                "product_name": i.product_name, "vendor": i.vendor, "cve_id": i.cve_id,
                "cvss_score": i.cvss_score, "epss_score": i.epss_score, "severity": i.severity,
                "is_kev": i.is_kev, "exploit_available": i.exploit_available,
                "patch_available": i.patch_available, "affected_versions": i.affected_versions,
                "confidence": i.confidence, "source_count": i.source_count,
                "targeted_sectors": i.targeted_sectors, "targeted_regions": i.targeted_regions,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            }
            for i in items
        ]
        return Response(
            content=json.dumps(rows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=vulnerable_products.json"},
        )

    # CSV
    lines = ["Product,Vendor,CVE,CVSS,EPSS,Severity,KEV,Exploit,Patch,Confidence,Sources,First Seen,Last Seen"]
    for i in items:
        lines.append(",".join([
            f'"{(i.product_name or "").replace(chr(34), chr(39))}"',
            f'"{(i.vendor or "").replace(chr(34), chr(39))}"',
            i.cve_id or "",
            f"{i.cvss_score:.1f}" if i.cvss_score is not None else "",
            f"{i.epss_score:.2f}" if i.epss_score is not None else "",
            i.severity,
            str(i.is_kev), str(i.exploit_available), str(i.patch_available),
            i.confidence, str(i.source_count),
            i.first_seen.isoformat() if i.first_seen else "",
            i.last_seen.isoformat() if i.last_seen else "",
        ]))
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerable_products.csv"},
    )


@router.get("/threat-campaigns/export")
async def export_threat_campaigns(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("csv", pattern="^(csv|json)$"),
    window: str = Query("all", pattern="^(7d|all)$"),
):
    """Export threat campaigns as CSV or JSON."""
    from app.services.intel_extraction import get_threat_campaigns

    window_days = 7 if window == "7d" else None
    items, _ = await get_threat_campaigns(db, limit=5000, window_days=window_days)

    if format == "json":
        import json
        rows = [
            {
                "actor_name": i.actor_name, "campaign_name": i.campaign_name,
                "severity": i.severity, "confidence": i.confidence,
                "malware_used": i.malware_used, "techniques_used": i.techniques_used,
                "cves_exploited": i.cves_exploited, "targeted_sectors": i.targeted_sectors,
                "targeted_regions": i.targeted_regions, "source_count": i.source_count,
                "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                "last_seen": i.last_seen.isoformat() if i.last_seen else None,
            }
            for i in items
        ]
        return Response(
            content=json.dumps(rows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threat_campaigns.json"},
        )

    # CSV
    lines = ["Actor,Campaign,Severity,Confidence,Malware,Techniques,CVEs,Sectors,Regions,Sources,First Seen,Last Seen"]
    for i in items:
        lines.append(",".join([
            f'"{(i.actor_name or "").replace(chr(34), chr(39))}"',
            f'"{(i.campaign_name or "").replace(chr(34), chr(39))}"',
            i.severity, i.confidence,
            f'"{";".join(i.malware_used)}"',
            f'"{";".join(i.techniques_used)}"',
            f'"{";".join(i.cves_exploited)}"',
            f'"{";".join(i.targeted_sectors)}"',
            f'"{";".join(i.targeted_regions)}"',
            str(i.source_count),
            i.first_seen.isoformat() if i.first_seen else "",
            i.last_seen.isoformat() if i.last_seen else "",
        ]))
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_campaigns.csv"},
    )


@router.post("/cve-lookup")
async def bulk_cve_lookup(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict,
):
    """Bulk lookup CVEs — accepts {"cves": ["CVE-2024-1234", ...]}."""
    from app.models.models import VulnerableProduct

    raw_cves = payload.get("cves", [])
    if not raw_cves or not isinstance(raw_cves, list):
        raise HTTPException(400, "Provide a 'cves' array")
    if len(raw_cves) > 200:
        raise HTTPException(400, "Maximum 200 CVEs per lookup")

    # Validate CVE format
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    cves = [c.strip().upper() for c in raw_cves if cve_pattern.match(c.strip())]
    if not cves:
        raise HTTPException(400, "No valid CVE IDs provided")

    result = await db.execute(
        select(VulnerableProduct).where(VulnerableProduct.cve_id.in_(cves))
    )
    items = result.scalars().all()

    found = {i.cve_id: VulnerableProductResponse.model_validate(i) for i in items}
    return {
        "requested": len(cves),
        "found": len(found),
        "missing": [c for c in cves if c not in found],
        "results": {cve: found[cve].model_dump() for cve in cves if cve in found},
    }


@router.get("/vendor-stats")
async def vendor_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get top vendors by vulnerable product count."""
    from app.services.intel_extraction import get_vendor_stats

    ck = cache_key("vendor_stats")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = await get_vendor_stats(db)
    await set_cached(ck, data, ttl=120)
    return data


@router.patch("/vulnerable-products/{product_id}/false-positive")
async def toggle_product_false_positive(
    product_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
    value: bool = Query(True),
):
    """Mark/unmark a vulnerable product as false positive."""
    result = await db.execute(select(VulnerableProduct).where(VulnerableProduct.id == product_id))
    product = result.scalar_one_or_none()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    product.is_false_positive = value
    await db.commit()
    return {"id": str(product_id), "is_false_positive": value}


@router.patch("/threat-campaigns/{campaign_id}/false-positive")
async def toggle_campaign_false_positive(
    campaign_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
    value: bool = Query(True),
):
    """Mark/unmark a threat campaign as false positive."""
    result = await db.execute(select(ThreatCampaign).where(ThreatCampaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    campaign.is_false_positive = value
    await db.commit()
    return {"id": str(campaign_id), "is_false_positive": value}


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


# ── HTML Report Builder ───────────────────────────────────

def _highlight_keywords_html(text: str) -> str:
    """Apply keyword highlighting to text for HTML reports."""
    rules = [
        (r'\b(CVE-\d{4}-\d{4,})\b', r'<span class="kw-cve">\1</span>'),
        (r'\b(T\d{4}(?:\.\d{3})?)\b', r'<span class="kw-mitre">\1</span>'),
        (r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', r'<span class="kw-ip">\1</span>'),
        (r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', r'<span class="kw-hash">\1</span>'),
        (r'(?i)\b(APT\d+|UNC\d+|UAT-\d+|FIN\d+|Lazarus|Fancy Bear|Cozy Bear|Turla|Sandworm|Kimsuky|ScarCruft)\b', r'<span class="kw-ta">\1</span>'),
        (r'\b(\d{4}-\d{2}-\d{2})\b', r'<span class="kw-date">\1</span>'),
    ]
    for pattern, repl in rules:
        text = re.sub(pattern, repl, text)
    return text


def _build_report_html(item: NewsItemResponse) -> str:
    """Generate a self-contained HTML intelligence report with keyword highlighting."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pub = item.published_at.strftime("%Y-%m-%d %H:%M UTC") if item.published_at else "Unknown"
    cat_label = _CAT_LABELS.get(item.category.value if hasattr(item.category, 'value') else item.category, str(item.category))
    prio = getattr(item, "recommended_priority", "medium") or "medium"
    prio_label = _PRIORITY_LABELS.get(prio, prio)

    prio_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
    prio_color = prio_colors.get(prio, "#eab308")

    def h(t: str) -> str:
        """Escape & highlight."""
        import html as html_mod
        t = html_mod.escape(t)
        return _highlight_keywords_html(t)

    def bullets(items: list[str], icon: str = "▸") -> str:
        if not items:
            return ""
        return "".join(f'<li><span class="bullet-icon">{icon}</span> {h(i)}</li>' for i in items)

    sections: list[str] = []

    # Executive Summary
    if item.summary:
        sections.append(f'<section><h2>Executive Summary</h2><p>{h(item.summary)}</p></section>')

    # Intelligence Brief
    brief = getattr(item, "executive_brief", None)
    if brief:
        sections.append(f'<section><h2>Intelligence Brief</h2><p>{h(brief)}</p></section>')

    # Risk Assessment + Attack Narrative (side-by-side)
    risk = getattr(item, "risk_assessment", None)
    narrative = getattr(item, "attack_narrative", None)
    if risk or narrative:
        cols = ""
        if risk:
            cols += f'<div class="col"><h3>&#9888; Risk Assessment</h3><p>{h(risk)}</p></div>'
        if narrative:
            cols += f'<div class="col"><h3>&#9876; Attack Narrative</h3><p>{h(narrative)}</p></div>'
        sections.append(f'<section class="grid-2">{cols}</section>')

    # Key Takeaways
    if item.why_it_matters:
        sections.append(f'<section><h2>Key Takeaways</h2><ul class="action-list">{bullets(item.why_it_matters, "⚡")}</ul></section>')

    # Threat Landscape
    threat_parts = []
    if item.threat_actors:
        threat_parts.append(f'<div class="tag-group"><span class="tag-label">Threat Actors</span>{"".join(f"<span class=&quot;tag tag-ta&quot;>{h(t)}</span>" for t in item.threat_actors)}</div>')
    if item.malware_families:
        threat_parts.append(f'<div class="tag-group"><span class="tag-label">Malware / Tools</span>{"".join(f"<span class=&quot;tag tag-mal&quot;>{h(t)}</span>" for t in item.malware_families)}</div>')
    if item.cves:
        threat_parts.append(f'<div class="tag-group"><span class="tag-label">CVEs</span>{"".join(f"<span class=&quot;tag tag-cve&quot;>{h(c)}</span>" for c in item.cves)}</div>')
    if item.vulnerable_products:
        threat_parts.append(f'<div class="tag-group"><span class="tag-label">Affected Products</span>{"".join(f"<span class=&quot;tag tag-prod&quot;>{h(p)}</span>" for p in item.vulnerable_products)}</div>')
    if threat_parts:
        sections.append(f'<section><h2>Threat Landscape</h2>{"".join(threat_parts)}</section>')

    # MITRE ATT&CK
    if item.tactics_techniques:
        sections.append(f'<section><h2>MITRE ATT&CK</h2><ul class="action-list">{bullets(item.tactics_techniques, "🎯")}</ul></section>')

    # Post-Exploitation
    if item.post_exploitation:
        sections.append(f'<section><h2>Post-Exploitation</h2><ul class="action-list">{bullets(item.post_exploitation, "⚔")}</ul></section>')

    # Targeting
    targeting = []
    if item.targeted_sectors:
        targeting.append(f'<strong>Sectors:</strong> {", ".join(h(s) for s in item.targeted_sectors)}')
    if item.targeted_regions:
        targeting.append(f'<strong>Regions:</strong> {", ".join(h(r) for r in item.targeted_regions)}')
    if item.impacted_assets:
        targeting.append(f'<strong>Impacted Assets:</strong> {", ".join(h(a) for a in item.impacted_assets)}')
    if targeting:
        sections.append(f'<section><h2>Targeting</h2><p>{" &nbsp;|&nbsp; ".join(targeting)}</p></section>')

    # IOC Summary
    ioc = item.ioc_summary or {}
    ioc_rows = ""
    for ioc_type, key in [("Domain", "domains"), ("IP", "ips"), ("Hash", "hashes"), ("URL", "urls")]:
        for val in (ioc.get(key) or []):
            ioc_rows += f'<tr><td class="ioc-type">{ioc_type}</td><td class="ioc-val">{h(val)}</td></tr>'
    if ioc_rows:
        sections.append(f'<section><h2>Indicators of Compromise</h2><table class="ioc-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>{ioc_rows}</tbody></table></section>')

    # Timeline
    if item.timeline:
        tl = "".join(f'<div class="tl-item"><span class="tl-date">{(ev.get("date") or "N/A")}</span><span class="tl-event">{h(ev.get("event", ""))}</span></div>' for ev in item.timeline)
        sections.append(f'<section><h2>Timeline</h2><div class="timeline">{tl}</div></section>')

    # Detection & Mitigation
    if item.detection_opportunities or item.mitigation_recommendations:
        cols = ""
        if item.detection_opportunities:
            cols += f'<div class="col"><h3>&#128269; Detection</h3><ul class="action-list">{bullets(item.detection_opportunities, "▸")}</ul></div>'
        if item.mitigation_recommendations:
            cols += f'<div class="col"><h3>&#9989; Mitigation</h3><ul class="action-list">{bullets(item.mitigation_recommendations, "✓")}</ul></div>'
        sections.append(f'<section class="grid-2">{cols}</section>')

    # Tags
    if item.tags:
        tag_html = "".join(f'<span class="tag">{h(t)}</span>' for t in item.tags)
        sections.append(f'<section class="tags-section">{tag_html}</section>')

    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntelWatch Report — {h(item.headline)}</title>
<style>
:root{{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#e2e2e8;--muted:#888;--accent:#6366f1;--red:#ef4444;--orange:#f97316;--yellow:#eab308;--green:#22c55e;--blue:#3b82f6;--purple:#a855f7;--sky:#38bdf8;}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;font-size:13px;padding:24px}}
.container{{max-width:900px;margin:0 auto}}
.header{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}}
.header h1{{font-size:18px;line-height:1.3;margin-bottom:12px}}
.meta-row{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:11px;color:var(--muted)}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;border:1px solid}}
.badge-cat{{border-color:{prio_color}40;color:{prio_color};background:{prio_color}10}}
.badge-prio{{border-color:{prio_color};color:{prio_color};background:{prio_color}15}}
.badge-score{{border-color:var(--sky);color:var(--sky)}}
.classification{{text-align:center;font-size:10px;padding:6px;background:#22c55e15;color:var(--green);border:1px solid #22c55e30;border-radius:8px;margin-bottom:16px;letter-spacing:1px;font-weight:600}}
section{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:12px}}
h2{{font-size:14px;font-weight:600;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}}
h3{{font-size:12px;font-weight:600;margin-bottom:8px;color:var(--muted)}}
p{{margin-bottom:8px;font-size:12px;color:var(--muted)}}
.grid-2{{display:grid;grid-template-columns:1fr 1fr;gap:16px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin-bottom:12px}}
.grid-2 .col{{}}
.action-list{{list-style:none;padding:0}}
.action-list li{{font-size:11px;color:var(--muted);padding:4px 0;display:flex;gap:6px;align-items:flex-start;line-height:1.5}}
.bullet-icon{{color:var(--accent);font-size:10px;flex-shrink:0;margin-top:2px}}
.tag-group{{margin-bottom:8px}}
.tag-label{{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:4px}}
.tag{{display:inline-block;font-size:10px;padding:2px 8px;border-radius:4px;margin:2px;border:1px solid var(--border);background:var(--bg)}}
.tag-ta{{border-color:var(--purple);color:var(--purple)}}
.tag-mal{{border-color:var(--red);color:var(--red)}}
.tag-cve{{border-color:var(--orange);color:var(--orange)}}
.tag-prod{{border-color:var(--yellow);color:var(--yellow)}}
.ioc-table{{width:100%;border-collapse:collapse;font-size:11px}}
.ioc-table th{{text-align:left;padding:6px 8px;background:var(--bg);border:1px solid var(--border);font-size:10px;text-transform:uppercase;color:var(--muted)}}
.ioc-table td{{padding:5px 8px;border:1px solid var(--border)}}
.ioc-type{{font-weight:600;width:60px;color:var(--sky)}}
.ioc-val{{font-family:monospace;font-size:10px;word-break:break-all}}
.timeline{{padding-left:16px;border-left:2px solid var(--accent)}}
.tl-item{{margin-bottom:10px;padding-left:12px;position:relative}}
.tl-item::before{{content:'';position:absolute;left:-21px;top:6px;width:8px;height:8px;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}}
.tl-date{{font-size:10px;font-weight:600;color:var(--accent);display:block}}
.tl-event{{font-size:11px;color:var(--muted)}}
.tags-section{{display:flex;flex-wrap:wrap;gap:4px}}
.kw-cve{{font-weight:600;color:var(--orange);background:#f9731610;padding:0 3px;border-radius:3px}}
.kw-mitre{{font-weight:600;color:var(--blue);background:#3b82f610;padding:0 3px;border-radius:3px}}
.kw-ip{{font-family:monospace;color:var(--sky);background:#38bdf810;padding:0 3px;border-radius:3px;font-size:11px}}
.kw-hash{{font-family:monospace;color:var(--purple);background:#a855f710;padding:0 3px;border-radius:3px;font-size:9px}}
.kw-ta{{font-weight:600;color:var(--purple)}}
.kw-date{{color:var(--accent);font-weight:500}}
.footer{{text-align:center;font-size:10px;color:var(--muted);padding-top:16px;border-top:1px solid var(--border);margin-top:20px}}
@media print{{body{{background:#fff;color:#111;font-size:11px;padding:12px}} section,.header{{background:#fafafa;border-color:#ddd}} .kw-cve,.kw-mitre,.kw-ip,.kw-hash{{background:#eee}} }}
</style></head><body>
<div class="container">
<div class="classification">▪ TLP:GREEN ▪ INTELWATCH INTELLIGENCE REPORT ▪ {now} ▪</div>
<div class="header">
<h1>{h(item.headline)}</h1>
<div class="meta-row">
<span class="badge badge-cat">{cat_label}</span>
<span class="badge badge-prio">{prio_label}</span>
<span class="badge badge-score">Relevance: {item.relevance_score}/100</span>
<span class="badge" style="border-color:var(--muted)">{item.confidence} confidence</span>
<span style="margin-left:auto">Source: {h(item.source)} &nbsp;|&nbsp; Published: {pub}</span>
</div>
</div>
{"".join(sections)}
<div class="footer">
<p>Source: <a href="{item.source_url}" style="color:var(--accent)">{item.source_url}</a></p>
<p>Auto-generated by IntelWatch Cyber News Intelligence. AI-enriched analysis may contain inferences.</p>
</div>
</div></body></html>'''


# ── PDF Report Builder ────────────────────────────────────

def _build_report_pdf(item: NewsItemResponse) -> bytes:
    """Generate a professional PDF intelligence report using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=20*mm, bottomMargin=18*mm)

    # Colors
    dark_bg = colors.HexColor("#0c0c14")
    accent = colors.HexColor("#6366f1")
    muted = colors.HexColor("#666680")
    red = colors.HexColor("#ef4444")
    orange = colors.HexColor("#f97316")
    green = colors.HexColor("#22c55e")
    blue = colors.HexColor("#3b82f6")
    border_c = colors.HexColor("#2a2a3e")

    # Styles
    styles = getSampleStyleSheet()
    s_title = ParagraphStyle("Title2", parent=styles["Normal"], fontSize=15, leading=19, fontName="Helvetica-Bold", textColor=colors.HexColor("#111"))
    s_h2 = ParagraphStyle("H2", parent=styles["Normal"], fontSize=11, leading=14, fontName="Helvetica-Bold", textColor=colors.HexColor("#222"), spaceBefore=10, spaceAfter=4)
    s_body = ParagraphStyle("Body2", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#333"), alignment=TA_JUSTIFY)
    s_bullet = ParagraphStyle("Bullet2", parent=s_body, leftIndent=12, bulletIndent=0, spaceBefore=2)
    s_small = ParagraphStyle("Small2", parent=styles["Normal"], fontSize=8, leading=10, textColor=muted)
    s_center = ParagraphStyle("Center2", parent=styles["Normal"], fontSize=8, leading=10, textColor=green, alignment=TA_CENTER)
    s_tag = ParagraphStyle("Tag2", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#555"))

    story: list = []

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pub = item.published_at.strftime("%Y-%m-%d %H:%M UTC") if item.published_at else "Unknown"
    cat_label = _CAT_LABELS.get(item.category.value if hasattr(item.category, 'value') else item.category, str(item.category))
    prio = getattr(item, "recommended_priority", "medium") or "medium"
    prio_label = _PRIORITY_LABELS.get(prio, prio)

    # Classification banner
    story.append(Paragraph(f"▪ TLP:GREEN &nbsp;&nbsp;|&nbsp;&nbsp; INTELWATCH INTELLIGENCE REPORT &nbsp;&nbsp;|&nbsp;&nbsp; {now} ▪", s_center))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1, color=accent, spaceBefore=2, spaceAfter=6))

    # Title
    story.append(Paragraph(item.headline, s_title))
    story.append(Spacer(1, 6))

    # Meta table
    meta_data = [
        ["Category", cat_label, "Source", item.source],
        ["Priority", prio_label, "Published", pub],
        ["Relevance", f"{item.relevance_score}/100", "Confidence", item.confidence.upper()],
    ]
    if item.campaign_name:
        meta_data.append(["Campaign", item.campaign_name, "", ""])
    meta_table = Table(meta_data, colWidths=[65, 165, 60, 165])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), muted),
        ("TEXTCOLOR", (2, 0), (2, -1), muted),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#222")),
        ("TEXTCOLOR", (3, 0), (3, -1), colors.HexColor("#222")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.5, color=border_c, spaceAfter=6))

    def add_section(title: str, text: str | None = None, bullets_list: list[str] | None = None):
        if not text and not bullets_list:
            return
        story.append(Paragraph(title, s_h2))
        if text:
            # Highlight CVEs/IPs inline with bold
            text = re.sub(r'\b(CVE-\d{4}-\d{4,})\b', r'<b>\1</b>', text)
            text = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', r'<font color="#3b82f6">\1</font>', text)
            story.append(Paragraph(text, s_body))
        if bullets_list:
            for b in bullets_list:
                b = re.sub(r'\b(CVE-\d{4}-\d{4,})\b', r'<b>\1</b>', b)
                story.append(Paragraph(f"▸ {b}", s_bullet))
        story.append(Spacer(1, 4))

    # Content sections
    add_section("Executive Summary", item.summary)
    add_section("Intelligence Brief", getattr(item, "executive_brief", None))
    add_section("Risk Assessment", getattr(item, "risk_assessment", None))
    add_section("Attack Narrative", getattr(item, "attack_narrative", None))
    add_section("Key Takeaways", bullets_list=item.why_it_matters if item.why_it_matters else None)

    # Threat Landscape as tags
    tl_parts = []
    if item.threat_actors:
        tl_parts.append(f"<b>Threat Actors:</b> {', '.join(item.threat_actors)}")
    if item.malware_families:
        tl_parts.append(f"<b>Malware/Tools:</b> {', '.join(item.malware_families)}")
    if item.cves:
        tl_parts.append(f"<b>CVEs:</b> {', '.join(item.cves)}")
    if item.vulnerable_products:
        tl_parts.append(f"<b>Products:</b> {', '.join(item.vulnerable_products)}")
    if tl_parts:
        add_section("Threat Landscape", " &nbsp;|&nbsp; ".join(tl_parts))

    add_section("MITRE ATT&CK", bullets_list=item.tactics_techniques if item.tactics_techniques else None)
    add_section("Post-Exploitation", bullets_list=item.post_exploitation if item.post_exploitation else None)

    # Targeting
    tgt = []
    if item.targeted_sectors:
        tgt.append(f"<b>Sectors:</b> {', '.join(item.targeted_sectors)}")
    if item.targeted_regions:
        tgt.append(f"<b>Regions:</b> {', '.join(item.targeted_regions)}")
    if item.impacted_assets:
        tgt.append(f"<b>Assets:</b> {', '.join(item.impacted_assets)}")
    if tgt:
        add_section("Targeting", " &nbsp;|&nbsp; ".join(tgt))

    # IOC Table
    ioc = item.ioc_summary or {}
    ioc_rows = []
    for ioc_type, key in [("Domain", "domains"), ("IP", "ips"), ("Hash", "hashes"), ("URL", "urls")]:
        for val in (ioc.get(key) or []):
            ioc_rows.append([ioc_type, val])
    if ioc_rows:
        story.append(Paragraph("Indicators of Compromise", s_h2))
        tbl = Table([["Type", "Value"]] + ioc_rows, colWidths=[50, 405])
        tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f5")),
            ("GRID", (0, 0), (-1, -1), 0.5, border_c),
            ("FONTNAME", (1, 1), (1, -1), "Courier"),
            ("FONTSIZE", (1, 1), (1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 6))

    # Timeline
    if item.timeline:
        story.append(Paragraph("Timeline", s_h2))
        for ev in item.timeline:
            story.append(Paragraph(f"<b>{ev.get('date') or 'N/A'}</b> — {ev.get('event', '')}", s_bullet))
        story.append(Spacer(1, 4))

    add_section("Detection Opportunities", bullets_list=item.detection_opportunities if item.detection_opportunities else None)
    add_section("Mitigation Recommendations", bullets_list=item.mitigation_recommendations if item.mitigation_recommendations else None)

    # Tags
    if item.tags:
        story.append(Paragraph(f"Tags: {', '.join(item.tags)}", s_tag))
        story.append(Spacer(1, 6))

    # Footer
    story.append(HRFlowable(width="100%", thickness=0.5, color=border_c, spaceBefore=8, spaceAfter=4))
    story.append(Paragraph(f"Source: {item.source_url}", s_small))
    story.append(Paragraph("Auto-generated by IntelWatch Cyber News Intelligence. AI-enriched analysis may contain inferences.", s_small))

    doc.build(story)
    return buf.getvalue()


@router.get("/{news_id}/report")
async def generate_news_report(
    news_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("pdf", pattern="^(pdf|html|markdown)$"),
):
    """Generate a downloadable intelligence report (PDF, HTML, or Markdown)."""
    result = await db.execute(
        select(NewsItem).where(NewsItem.id == news_id)
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="News item not found")

    news_response = NewsItemResponse.model_validate(item)
    safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in item.headline[:60]).strip()

    if format == "html":
        html_content = _build_report_html(news_response)
        return Response(
            content=html_content,
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="IntelWatch-Report-{safe_title}.html"',
            },
        )
    elif format == "pdf":
        pdf_bytes = _build_report_pdf(news_response)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="IntelWatch-Report-{safe_title}.pdf"',
            },
        )
    else:
        report_md = _build_report_markdown(news_response)
        return Response(
            content=report_md,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="IntelWatch-Report-{safe_title}.md"',
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
