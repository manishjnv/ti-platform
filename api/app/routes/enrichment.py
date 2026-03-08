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

from app.prompts import BRIEFING_GEN_PROMPT

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
    from app.services.ai import chat_completion_json
    import json, logging
    from datetime import datetime, timedelta, timezone

    def _jsonify(obj):
        """Deep-convert datetime objects to ISO strings for JSONB storage."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {k: _jsonify(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_jsonify(v) for v in obj]
        return obj

    days = payload.get("days", 7)
    data = await ce.collect_briefing_data(db, days=days)
    now = datetime.now(timezone.utc)
    period_start = now - timedelta(days=days)

    # Build prompt for AI
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
  "title": "Weekly Threat Brief",
  "executive_summary": "2-3 paragraph executive overview of the most critical threats, campaigns, and vulnerabilities observed.",
  "key_findings": ["finding1", "finding2", ...],
  "recommendations": ["rec1", "rec2", ...],
  "sections": [
    {{"heading": "...", "content": "..."}}
  ]
}}"""

    briefing = await chat_completion_json(
        system_prompt=BRIEFING_GEN_PROMPT,
        user_prompt=prompt,
        max_tokens=4000,
        required_keys=["executive_summary"],
        caller="briefing_gen",
        feature="intel_enrichment",
    )

    # Store in DB — use AI JSON if available, fall back to data-only briefing
    from app.models.models import ThreatBriefing
    title = (briefing or {}).get("title", "Weekly Threat Brief")
    exec_summary = (briefing or {}).get("executive_summary", "")
    recommendations = (briefing or {}).get("recommendations", [])

    # If AI failed, build a minimal executive summary from the raw data
    if not exec_summary:
        logging.warning("briefing_ai_failed: building summary from raw data")
        parts = []
        stats = data.get("stats", {})
        parts.append(f"Over the past {days} days, IntelWatch processed {stats.get('articles_processed', 0)} articles, identified {stats.get('new_cves', 0)} CVEs and tracked {stats.get('new_campaigns', 0)} active campaigns.")
        if data.get("campaigns"):
            top = [c.get("campaign_name") or c.get("actor_name", "") for c in data["campaigns"][:5]]
            parts.append(f"Top active campaigns include: {', '.join(top)}.")
        if data.get("trending_cves"):
            top_cves = [c.get("cve_id", "") for c in data["trending_cves"][:5]]
            parts.append(f"Trending vulnerabilities: {', '.join(top_cves)}.")
        exec_summary = " ".join(parts)

    tb = ThreatBriefing(
        period="weekly" if days >= 7 else "daily",
        period_start=period_start,
        period_end=now,
        title=title,
        executive_summary=exec_summary,
        key_campaigns=_jsonify(data["campaigns"][:10]),
        key_vulnerabilities=_jsonify(data["trending_cves"][:10]),
        key_actors=_jsonify(data["actors"][:10]),
        sector_threats=_jsonify({"sectors": data["sector_threats"]}),
        stats=_jsonify(data["stats"]),
        recommendations=recommendations,
        raw_data=_jsonify(briefing or {}),
    )
    db.add(tb)
    await db.commit()
    return {
        "id": str(tb.id),
        "briefing": {
            "title": tb.title,
            "executive_summary": tb.executive_summary,
            "period": tb.period,
            "period_start": tb.period_start.isoformat() if tb.period_start else None,
            "period_end": tb.period_end.isoformat() if tb.period_end else None,
            "key_campaigns": tb.key_campaigns,
            "key_vulnerabilities": tb.key_vulnerabilities,
            "key_actors": tb.key_actors,
            "stats": tb.stats,
            "recommendations": tb.recommendations,
            "key_findings": (briefing or {}).get("key_findings", []),
            "sections": (briefing or {}).get("sections", []),
        },
    }


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
