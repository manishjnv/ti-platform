"""Intel items endpoints — feed listing, detail, export, enrichment."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select, or_, and_, cast
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import Text as SAText

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings
from app.core.logging import get_logger
from app.middleware.auth import get_current_user, require_viewer
from app.models.models import IntelItem, User
from app.schemas import IntelItemListResponse, IntelItemResponse
from app.services import database as db_service
from app.services.ai import chat_completion
from app.services.export import export_to_excel

router = APIRouter(prefix="/intel", tags=["intel"])
settings = get_settings()
logger = get_logger("intel")


@router.get("", response_model=IntelItemListResponse)
async def list_intel_items(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    feed_type: str | None = None,
    source_name: str | None = None,
    asset_type: str | None = None,
    is_kev: bool | None = None,
    exploit_available: bool | None = None,
    query: str | None = Query(None, max_length=200),
    sort_by: str = Query("ingested_at", pattern="^(ingested_at|risk_score|severity|published_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    """List intel items with pagination and filters."""
    ck = cache_key("intel_list", page, page_size, severity, feed_type, source_name, asset_type, is_kev, exploit_available, query, sort_by, sort_order)
    cached = await get_cached(ck)
    if cached:
        return cached

    items, total = await db_service.get_intel_items(
        db,
        page=page,
        page_size=page_size,
        severity=severity,
        feed_type=feed_type,
        source_name=source_name,
        asset_type=asset_type,
        is_kev=is_kev,
        exploit_available=exploit_available,
        search=query,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    pages = max(1, (total + page_size - 1) // page_size)
    response = IntelItemListResponse(
        items=[IntelItemResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )

    await set_cached(ck, response.model_dump(), ttl=30)
    return response


@router.get("/export")
async def export_intel(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = None,
    feed_type: str | None = None,
    page_size: int = Query(500, ge=1, le=5000),
):
    """Export intel items to Excel."""
    items, _ = await db_service.get_intel_items(
        db, page=1, page_size=page_size, severity=severity, feed_type=feed_type
    )

    item_dicts = [
        IntelItemResponse.model_validate(i).model_dump() for i in items
    ]
    excel_bytes = export_to_excel(item_dicts)

    filename = f"threat_intel_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return Response(
        content=excel_bytes.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{item_id}", response_model=IntelItemResponse)
async def get_intel_item(
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a single intel item by ID."""
    item = await db_service.get_intel_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intel item not found")
    return IntelItemResponse.model_validate(item)


# ─── Enrichment ──────────────────────────────────────────

_ENRICHMENT_SYSTEM_PROMPT = """You are an expert cyber threat intelligence analyst. Given an intel item, produce a structured JSON enrichment analysis. Return ONLY valid JSON with these keys:

{
  "executive_summary": "2-3 sentence executive brief for decision makers",
  "threat_actors": [{"name": "APT group or actor name", "aliases": ["other names"], "motivation": "financial/espionage/hacktivism/unknown", "confidence": "high/medium/low", "description": "1 sentence about this actor's involvement"}],
  "attack_techniques": [{"technique_id": "T1xxx or T1xxx.xxx", "technique_name": "Name", "tactic": "tactic-name", "description": "How this technique relates to this threat", "mitigations": ["mitigation 1"]}],
  "affected_versions": [{"product": "Product Name", "vendor": "Vendor", "versions_affected": "< 5.2.1 or specific range", "fixed_version": "5.2.1 or null if unknown", "patch_url": "URL or null", "cpe": "cpe string or null"}],
  "timeline_events": [{"date": "YYYY-MM-DD or null", "event": "Event title", "description": "What happened", "type": "disclosure/publication/patch/exploit/kev/advisory/update"}],
  "notable_campaigns": [{"name": "Campaign or breach name", "date": "YYYY or approximate", "description": "Brief description", "impact": "Impact description"}],
  "exploitation_info": {"epss_estimate": 0.0 to 1.0, "exploit_maturity": "none/poc/weaponized/unknown", "in_the_wild": true/false, "ransomware_use": true/false, "description": "Brief exploitation context"},
  "remediation": {"priority": "critical/high/medium/low", "guidance": ["Step 1", "Step 2"], "workarounds": ["Workaround if no patch"], "references": [{"title": "Reference name", "url": "URL"}]},
  "related_cves": ["CVE-YYYY-NNNNN"],
  "tags_suggested": ["tag1", "tag2"]
}

Rules:
- Only include data you are confident about. Leave arrays empty if unsure.
- For CVEs, base analysis on known vulnerability data. Include NVD publication, vendor advisory, and exploit dates when known.
- For threat actors, only name those with documented associations.
- Be specific with version info. If unknown, set fixed_version to null.
- EPSS estimate: provide your best estimate of exploitation probability (0-1 scale).
- Return ONLY the JSON object, no markdown, no explanation."""


@router.get("/{item_id}/enrichment")
async def get_intel_enrichment(
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """AI-powered enrichment analysis for an intel item."""
    # Check cache first
    ck = cache_key("intel_enrichment", str(item_id))
    cached = await get_cached(ck)
    if cached:
        return cached

    # Get item
    item = await db_service.get_intel_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intel item not found")

    # Build prompt
    parts = [
        f"Title: {item.title}",
        f"Severity: {item.severity}",
        f"Risk Score: {item.risk_score}/100",
        f"Source: {item.source_name}",
        f"Feed Type: {item.feed_type}",
        f"Published: {item.published_at.isoformat() if item.published_at else 'N/A'}",
    ]
    if item.description:
        parts.append(f"Description: {item.description[:2000]}")
    if item.cve_ids:
        parts.append(f"CVE IDs: {', '.join(item.cve_ids[:10])}")
    if item.affected_products:
        parts.append(f"Affected Products: {', '.join(item.affected_products[:10])}")
    if item.tags:
        parts.append(f"Tags: {', '.join(item.tags[:15])}")
    if item.is_kev:
        parts.append("This vulnerability is in CISA KEV (Known Exploited Vulnerabilities)")
    if item.exploit_available:
        parts.append("Exploits are known to be available")
    if item.exploitability_score is not None:
        parts.append(f"CVSS/Exploitability Score: {item.exploitability_score}")
    if item.geo:
        parts.append(f"Geographic context: {', '.join(item.geo[:10])}")
    if item.industries:
        parts.append(f"Industries: {', '.join(item.industries[:10])}")
    if item.ai_summary:
        parts.append(f"AI Summary: {item.ai_summary[:500]}")

    user_prompt = "\n".join(parts)

    # Call AI
    raw = await chat_completion(
        system_prompt=_ENRICHMENT_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        max_tokens=2000,
        temperature=0.2,
    )

    if not raw:
        # Return empty enrichment
        result = _empty_enrichment()
        return result

    # Parse JSON
    try:
        # Strip markdown fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        if cleaned.startswith("json"):
            cleaned = cleaned[4:].strip()

        enrichment = json.loads(cleaned)
    except (json.JSONDecodeError, Exception) as e:
        logger.warning("enrichment_parse_error", error=str(e), raw=raw[:200])
        enrichment = _empty_enrichment()

    # Cache for 6 hours
    await set_cached(ck, enrichment, ttl=21600)
    return enrichment


def _empty_enrichment() -> dict:
    return {
        "executive_summary": None,
        "threat_actors": [],
        "attack_techniques": [],
        "affected_versions": [],
        "timeline_events": [],
        "notable_campaigns": [],
        "exploitation_info": {
            "epss_estimate": None,
            "exploit_maturity": "unknown",
            "in_the_wild": False,
            "ransomware_use": False,
            "description": None,
        },
        "remediation": {
            "priority": None,
            "guidance": [],
            "workarounds": [],
            "references": [],
        },
        "related_cves": [],
        "tags_suggested": [],
    }


# ─── Related Intel (DB-based) ─────────────────────────────

@router.get("/{item_id}/related")
async def get_related_intel(
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(20, ge=1, le=50),
):
    """Find related intel items based on shared CVEs, tags, and products."""
    ck = cache_key("intel_related", str(item_id), limit)
    cached = await get_cached(ck)
    if cached:
        return cached

    item = await db_service.get_intel_item_by_id(db, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Intel item not found")

    # Build overlap conditions using PostgreSQL && operator
    conditions = []
    if item.cve_ids:
        conditions.append(IntelItem.cve_ids.op("&&")(cast(item.cve_ids, ARRAY(SAText))))
    if item.tags:
        conditions.append(IntelItem.tags.op("&&")(cast(item.tags, ARRAY(SAText))))
    if item.affected_products:
        conditions.append(IntelItem.affected_products.op("&&")(cast(item.affected_products, ARRAY(SAText))))

    if not conditions:
        return []

    query = (
        select(IntelItem)
        .where(
            and_(
                IntelItem.id != item.id,
                or_(*conditions),
            )
        )
        .order_by(IntelItem.risk_score.desc())
        .limit(limit)
    )
    result = await db.execute(query)
    rows = result.scalars().all()

    related = []
    for r in rows:
        # Determine relationship type
        rel_type = "related"
        shared_cves = set(r.cve_ids or []) & set(item.cve_ids or [])
        shared_tags = set(r.tags or []) & set(item.tags or [])
        shared_products = set(r.affected_products or []) & set(item.affected_products or [])

        if shared_cves:
            rel_type = "shared_cve"
        elif shared_products:
            rel_type = "shared_product"
        elif shared_tags:
            rel_type = "shared_tag"

        # Calculate confidence based on overlap
        overlap_score = len(shared_cves) * 40 + len(shared_products) * 30 + len(shared_tags) * 10
        confidence = min(95, max(20, overlap_score))

        related.append({
            "id": str(r.id),
            "title": r.title,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "source_name": r.source_name,
            "feed_type": r.feed_type,
            "ingested_at": r.ingested_at.isoformat(),
            "relationship_type": rel_type,
            "confidence": confidence,
            "shared_cves": list(shared_cves)[:5],
            "shared_tags": list(shared_tags)[:5],
            "shared_products": list(shared_products)[:3],
        })

    # Sort by confidence desc
    related.sort(key=lambda x: x["confidence"], reverse=True)

    await set_cached(ck, related, ttl=300)
    return related
