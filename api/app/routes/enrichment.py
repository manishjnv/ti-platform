"""Enrichment API routes — cross-functional intelligence endpoints.

Provides:
  - Dashboard enrichment (campaigns, actors, sectors, trending CVEs)
  - Intel item campaign/actor context
  - IOC campaign membership
  - Technique active usage from news
  - Threat velocity tracking
  - Org exposure scoring
  - Detection rule library
  - Threat briefings
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.middleware.auth import require_viewer
from app.models.models import User
from app.services import cross_enrichment as ce

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


# ─── Dashboard Enrichment ────────────────────────────────

@router.get("/dashboard")
async def dashboard_enrichment(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Active campaigns, top actors, sector threats, trending CVEs, campaign trend."""
    return await ce.get_dashboard_enrichment(db)


# ─── Intel Cross-Linking ────────────────────────────────

@router.post("/intel-context")
async def intel_campaign_context(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict,
):
    """Get campaign/actor context for an intel item via its CVEs and products."""
    cve_ids = payload.get("cve_ids", [])
    products = payload.get("products", [])
    return await ce.get_intel_campaign_context(db, cve_ids, products)


@router.post("/intel-batch")
async def intel_batch_enrichment(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict,
):
    """Batch-enrich multiple intel items with campaign/actor badges."""
    item_ids = payload.get("item_ids", [])
    if not item_ids or len(item_ids) > 100:
        return {}
    ck = cache_key(f"intel_batch:{'_'.join(sorted(item_ids[:10]))}")
    cached = await get_cached(ck)
    if cached:
        return cached
    result = await ce.get_intel_items_enriched(db, item_ids)
    await set_cached(ck, result, ttl=120)
    return result


# ─── IOC Cross-Linking ──────────────────────────────────

@router.get("/ioc-context")
async def ioc_campaign_context(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    value: str = Query(..., description="IOC value to look up"),
):
    """Find campaigns/actors associated with an IOC value."""
    return await ce.get_ioc_campaign_context(db, value)


# ─── Technique Cross-Linking ────────────────────────────

@router.get("/technique-usage")
async def technique_campaign_usage(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(30, ge=1, le=365),
):
    """ATT&CK technique usage heatmap from active news campaigns."""
    return await ce.get_technique_campaign_usage(db, days=days)


@router.get("/technique-detail")
async def technique_detail_enrichment(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    technique_id: str = Query(..., description="ATT&CK technique ID (e.g. T1566)"),
):
    """Detailed campaign/actor/sector data for a specific technique."""
    return await ce.get_technique_detail_enrichment(db, technique_id)


# ─── Threat Velocity ────────────────────────────────────

@router.get("/velocity")
async def threat_velocity(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Entities with accelerating news mention velocity."""
    return await ce.get_threat_velocity(db)


# ─── Org Exposure ───────────────────────────────────────

@router.post("/org-exposure")
async def org_exposure(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict,
):
    """Personalized threat exposure score based on org profile."""
    sectors = payload.get("sectors", [])
    regions = payload.get("regions", [])
    tech_stack = payload.get("tech_stack", [])
    return await ce.get_org_exposure(db, sectors, regions, tech_stack)


# ─── Detection Rules ───────────────────────────────────

@router.get("/detection-rules")
async def detection_rules(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    rule_type: str | None = Query(None, pattern="^(yara|kql|sigma)$"),
    severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    campaign: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    """Query the detection rule library."""
    return await ce.get_detection_rules(db, rule_type=rule_type, severity=severity, campaign=campaign, limit=limit)


@router.get("/detection-coverage")
async def detection_coverage(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Detection rule coverage statistics."""
    return await ce.get_detection_coverage(db)


@router.post("/detection-rules/sync")
async def sync_detection_rules(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Sync YARA/KQL rules from news articles into the detection rules library."""
    count = await ce.sync_detection_rules(db)
    return {"synced": count}


# ─── Threat Briefings ──────────────────────────────────

@router.get("/briefing-data")
async def briefing_data(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(7, ge=1, le=30),
):
    """Collect raw data for threat briefing generation."""
    return await ce.collect_briefing_data(db, days=days)


@router.post("/generate-briefing")
async def generate_briefing(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict,
):
    """Generate an AI threat briefing from collected data."""
    from app.services.ai import chat_completion

    days = payload.get("days", 7)
    data = await ce.collect_briefing_data(db, days=days)

    # Build prompt for AI
    import json
    prompt = f"""Generate a professional Weekly Threat Intelligence Briefing based on this data from the last {days} days.

DATA:
- Active Campaigns ({len(data['campaigns'])}): {json.dumps(data['campaigns'][:10], default=str)}
- Top Threat Actors ({len(data['actors'])}): {json.dumps(data['actors'][:10], default=str)}
- Sector Threats: {json.dumps(data['sector_threats'][:10], default=str)}
- Trending CVEs: {json.dumps(data['trending_cves'][:10], default=str)}
- Accelerating Threats: {json.dumps(data['velocity'][:5], default=str)}
- Stats: {json.dumps(data['stats'], default=str)}

FORMAT your response as JSON with these fields:
{{
  "title": "Weekly Threat Brief - [date range]",
  "executive_summary": "2-3 paragraph executive overview",
  "key_findings": ["finding1", "finding2", ...],
  "recommendations": ["rec1", "rec2", ...],
  "sections": [
    {{"heading": "...", "content": "..."}}
  ]
}}"""

    result = await chat_completion(
        system_prompt="You are a senior threat intelligence analyst. Generate comprehensive, actionable threat briefings in JSON format.",
        user_prompt=prompt,
        max_tokens=2000,
    )
    if not result:
        return {"error": "AI unavailable", "raw_data": data}

    try:
        # Try to parse JSON from AI response
        import re
        json_match = re.search(r'\{.*\}', result, re.DOTALL)
        if json_match:
            briefing = json.loads(json_match.group())
            # Store in DB
            from app.models.models import ThreatBriefing
            from datetime import datetime, timedelta, timezone
            now = datetime.now(timezone.utc)
            tb = ThreatBriefing(
                period="weekly" if days >= 7 else "daily",
                period_start=now - timedelta(days=days),
                period_end=now,
                title=briefing.get("title", f"Threat Brief - Last {days} days"),
                executive_summary=briefing.get("executive_summary", ""),
                key_campaigns=data["campaigns"][:10],
                key_vulnerabilities=data["trending_cves"][:10],
                key_actors=data["actors"][:10],
                sector_threats={"sectors": data["sector_threats"]},
                stats=data["stats"],
                recommendations=briefing.get("recommendations", []),
                raw_data=briefing,
            )
            db.add(tb)
            await db.commit()
            return {"briefing": briefing, "id": str(tb.id)}
    except (json.JSONDecodeError, Exception):
        pass

    return {"briefing_text": result, "raw_data": data}


@router.get("/briefings")
async def list_briefings(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50),
):
    """List past threat briefings."""
    from sqlalchemy import select
    from app.models.models import ThreatBriefing

    result = await db.execute(
        select(ThreatBriefing)
        .order_by(ThreatBriefing.created_at.desc())
        .limit(limit)
    )
    briefings = result.scalars().all()
    return [
        {
            "id": str(b.id),
            "period": b.period,
            "period_start": b.period_start.isoformat() if b.period_start else None,
            "period_end": b.period_end.isoformat() if b.period_end else None,
            "title": b.title,
            "executive_summary": b.executive_summary[:500],
            "key_campaigns": b.key_campaigns,
            "key_vulnerabilities": b.key_vulnerabilities,
            "key_actors": b.key_actors,
            "stats": b.stats,
            "recommendations": b.recommendations,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        }
        for b in briefings
    ]
