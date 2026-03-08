"""Intel items endpoints — feed listing, detail, export, enrichment."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select, or_, and_, cast, func, desc, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy import Text as SAText

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings
from app.core.logging import get_logger
from app.middleware.auth import get_current_user, require_viewer
from app.models.models import IntelItem, User, IOC, IntelIOCLink
from app.schemas import IntelItemListResponse, IntelItemResponse, IntelStatsResponse
from app.services import database as db_service
from app.services.ai import chat_completion_json
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
    geo: str | None = Query(None, max_length=100),
    industry: str | None = Query(None, max_length=200),
    sort_by: str = Query("ingested_at", pattern="^(ingested_at|risk_score|severity|published_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    """List intel items with pagination and filters."""
    ck = cache_key("intel_list", page, page_size, severity, feed_type, source_name, asset_type, is_kev, exploit_available, query, geo, industry, sort_by, sort_order)
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
        geo=geo,
        industry=industry,
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


@router.get("/stats", response_model=IntelStatsResponse)
async def intel_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Global stats for the Active Threats feed."""
    ck = cache_key("intel_stats")
    cached = await get_cached(ck)
    if cached:
        return cached

    from datetime import timedelta, timezone

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Single aggregate query
    row = (await db.execute(
        select(
            func.count().label("total"),
            func.count().filter(IntelItem.ingested_at >= day_ago).label("today"),
            func.count().filter(IntelItem.severity == text("'critical'::severity_level")).label("critical"),
            func.count().filter(IntelItem.severity == text("'high'::severity_level")).label("high"),
            func.count().filter(IntelItem.severity == text("'medium'::severity_level")).label("medium"),
            func.count().filter(IntelItem.severity == text("'low'::severity_level")).label("low"),
            func.count().filter(IntelItem.severity == text("'info'::severity_level")).label("info"),
            func.count().filter(IntelItem.is_kev.is_(True)).label("kev_count"),
            func.count().filter(IntelItem.exploit_available.is_(True)).label("exploit_count"),
            func.coalesce(func.avg(IntelItem.risk_score), 0).label("avg_risk"),
            func.count(func.distinct(IntelItem.source_name)).label("sources"),
            func.count().filter(IntelItem.ai_summary.isnot(None)).label("ai_enriched"),
        )
    )).one()

    # Top sources
    src_rows = (await db.execute(
        select(IntelItem.source_name, func.count().label("cnt"))
        .group_by(IntelItem.source_name)
        .order_by(desc("cnt"))
        .limit(10)
    )).all()
    top_sources = [{"name": r.source_name, "count": r.cnt} for r in src_rows]

    # Top tags (unnest array)
    tag_rows = (await db.execute(
        select(
            func.unnest(IntelItem.tags).label("tag"),
            func.count().label("cnt")
        ).group_by("tag").order_by(desc("cnt")).limit(15)
    )).all()
    top_tags = [r.tag for r in tag_rows]

    # Top CVEs
    cve_rows = (await db.execute(
        select(
            func.unnest(IntelItem.cve_ids).label("cve"),
            func.count().label("cnt")
        ).group_by("cve").order_by(desc("cnt")).limit(10)
    )).all()
    top_cves = [r.cve for r in cve_rows]

    # Feed type distribution
    ft_rows = (await db.execute(
        select(
            cast(IntelItem.feed_type, SAText).label("ft"),
            func.count().label("cnt"),
        ).group_by(IntelItem.feed_type)
    )).all()
    feed_type_counts = {r.ft: r.cnt for r in ft_rows}

    # Asset type distribution
    at_rows = (await db.execute(
        select(
            cast(IntelItem.asset_type, SAText).label("at"),
            func.count().label("cnt"),
        ).group_by(IntelItem.asset_type)
    )).all()
    asset_type_counts = {r.at: r.cnt for r in at_rows}

    response = IntelStatsResponse(
        total=row.total,
        today=row.today,
        critical=row.critical,
        high=row.high,
        medium=row.medium,
        low=row.low,
        info=row.info,
        kev_count=row.kev_count,
        exploit_count=row.exploit_count,
        avg_risk=int(row.avg_risk),
        sources=row.sources,
        ai_enriched=row.ai_enriched,
        top_sources=top_sources,
        top_tags=top_tags,
        top_cves=top_cves,
        feed_type_counts=feed_type_counts,
        asset_type_counts=asset_type_counts,
    )
    await set_cached(ck, response.model_dump(), ttl=60)
    return response


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

_ENRICHMENT_PROMPT_VERSION = "B-3.0"

_ENRICHMENT_SYSTEM_PROMPT = """You are a senior cyber threat intelligence analyst at a Fortune 100 SOC.

<output_format>
Respond with a single valid JSON object. No markdown fences, no commentary, no text outside the JSON.
</output_format>

<audience>
CISO: needs business-impact framing readable in ≤60 seconds.
SOC Analyst: needs detection rules, IOCs, and actionable technical details.
</audience>

<quality_rules>
BANNED — delete any sentence matching these patterns:
- "timely patching is crucial" / "apply patches and updates" / "keep software up to date"
- "monitor for suspicious activity" / "implement robust security controls"
- "organizations should prioritize security" / "stay vigilant"
- Any sentence that could apply generically to ANY intel item without modification.

REQUIRED — every sentence/bullet MUST include at least ONE of:
- A specific CVE, technology, tool name, protocol, or version number
- A concrete SIEM query, Sigma/Suricata rule, log source, or EDR detection
- A measurable action with clear owner and timeframe
- A named threat actor, malware hash, or campaign identifier
- A quantified business impact (dollar amount, record count, downtime)
</quality_rules>

<examples>
executive_summary:
  BAD: "This vulnerability highlights the importance of timely patching."
  GOOD: "CVE-2024-3400 allows unauthenticated RCE in PAN-OS GlobalProtect (10.2/11.0/11.1). Volexity confirmed active exploitation since March 26 by UTA0218. CISA KEV deadline: April 19."

detection_opportunities:
  BAD: "Monitor for suspicious network activity."
  GOOD: "Suricata rule — content:\"/ssl-vpn/hipreport.php\"; pcre:\"/SESSID=.*[;|`$]/\" — detects exploitation attempts on GlobalProtect."

remediation:
  BAD: "Apply the latest security patches."
  GOOD: "Apply PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3. Interim: enable Threat Prevention signature 95187 + disable device telemetry."
</examples>

<analysis_methodology>
Before generating output, reason through these steps internally:
1. Identify the core threat/vulnerability and its technical mechanism
2. Determine exploitation status: theoretical, PoC, weaponized, or active ITW
3. Map the attack chain from initial access to impact
4. Identify affected products with specific version boundaries
5. Derive detection opportunities from attack-chain observables
6. Formulate remediation steps in priority order
</analysis_methodology>

<json_schema>
{
  "executive_summary": "4-6 sentences: (1) specific threat/vuln with names+dates, (2) technical mechanism, (3) scope with numbers, (4) organizational impact. Zero filler.",
  "threat_actors": [{"name": "str", "aliases": ["str"], "motivation": "financial|espionage|hacktivism|unknown", "confidence": "high|medium|low", "description": "1 sentence on involvement"}],
  "attack_techniques": [{"technique_id": "T1xxx.xxx", "technique_name": "str", "tactic": "str", "description": "str", "mitigations": ["str"]}],
  "attack_narrative": "4-6 sentences step-by-step kill chain. Name tools, protocols, techniques at each stage. For vulns without known chain, describe most likely exploitation scenario.",
  "initial_access_vector": "Specific: 'Exploitation of internet-facing PAN-OS' | 'Phishing with ISO attachment' | null",
  "post_exploitation": ["Specific tools+actions: 'LSASS dump via Nanodump'. 2-5 items. [] if N/A."],
  "affected_versions": [{"product": "str", "vendor": "str", "versions_affected": "< x.y.z or range", "fixed_version": "str or null", "patch_url": "str or null", "cpe": "str or null"}],
  "timeline_events": [{"date": "YYYY-MM-DD or null", "event": "str", "description": "str", "type": "disclosure|publication|patch|exploit|kev|advisory|update"}],
  "notable_campaigns": [{"name": "str", "date": "YYYY", "description": "str", "impact": "str"}],
  "exploitation_info": {"epss_estimate": 0.0, "exploit_maturity": "none|poc|weaponized|unknown", "in_the_wild": false, "ransomware_use": false, "description": "str"},
  "detection_opportunities": ["3-5 items. Each MUST name a log source, query pattern, or signature ID. No vague 'monitor for anomalies'."],
  "ioc_summary": {"domains": [], "ips": [], "hashes": [], "urls": []},
  "targeted_sectors": ["Specific: 'Government — Defense', 'Financial Services — Banking'. ≥1 required."],
  "targeted_regions": ["Specific: 'South Korea', 'Western Europe'. ≥1 required."],
  "impacted_assets": ["Specific asset types: 'Palo Alto GlobalProtect VPN appliances'. Not generic 'endpoints'."],
  "remediation": {"priority": "critical|high|medium|low", "guidance": ["Step must name specific fix: patch version, config change, GPO"], "workarounds": ["Specific interim measure if no patch"], "references": [{"title": "str", "url": "str"}]},
  "related_cves": ["CVE-YYYY-NNNNN — co-exploited or chained CVEs"],
  "tags_suggested": ["str"],
  "recommended_priority": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "source_reliability": "authoritative|credible|speculative|unknown"
}
</json_schema>

<grounding_rules>
- Only include data supported by the input. Leave arrays empty ([]) if uncertain.
- For CVEs: include NVD publication, vendor advisory, and known exploit dates.
- For threat actors: only name those with documented associations.
- Be specific with versions. Use null for unknown fixed_version.
- EPSS: estimate exploitation probability 0.0–1.0 based on available evidence.
- Return ONLY the JSON object.
</grounding_rules>"""


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

    # Call AI with JSON validation and retry
    enrichment = await chat_completion_json(
        system_prompt=_ENRICHMENT_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        max_tokens=3000,
        temperature=0.2,
        required_keys=["executive_summary", "threat_actors", "attack_techniques"],
        caller="intel_enrichment",
        feature="intel_enrichment",
    )

    if not enrichment:
        enrichment = _empty_enrichment()
    else:
        enrichment["_prompt_version"] = _ENRICHMENT_PROMPT_VERSION

    # Cache for 6 hours
    await set_cached(ck, enrichment, ttl=21600)
    return enrichment


def _empty_enrichment() -> dict:
    return {
        "executive_summary": None,
        "threat_actors": [],
        "attack_techniques": [],
        "attack_narrative": None,
        "initial_access_vector": None,
        "post_exploitation": [],
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
        "detection_opportunities": [],
        "ioc_summary": {"domains": [], "ips": [], "hashes": [], "urls": []},
        "targeted_sectors": [],
        "targeted_regions": [],
        "impacted_assets": [],
        "remediation": {
            "priority": None,
            "guidance": [],
            "workarounds": [],
            "references": [],
        },
        "related_cves": [],
        "tags_suggested": [],
        "recommended_priority": None,
        "confidence": None,
        "source_reliability": None,
        "_prompt_version": _ENRICHMENT_PROMPT_VERSION,
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


# ─── Linked IOCs ─────────────────────────────────────────

@router.get("/{item_id}/iocs")
async def get_intel_iocs(
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(50, ge=1, le=200),
):
    """Get IOCs linked to this intel item."""
    ck = cache_key("intel_iocs", str(item_id), limit)
    cached = await get_cached(ck)
    if cached:
        return cached

    query = (
        select(IOC, IntelIOCLink.relationship)
        .join(IntelIOCLink, IOC.id == IntelIOCLink.ioc_id)
        .where(IntelIOCLink.intel_id == item_id)
        .order_by(desc(IOC.risk_score), desc(IOC.last_seen))
        .limit(limit)
    )
    rows = (await db.execute(query)).all()

    iocs = []
    for r in rows:
        ioc = r.IOC
        internetdb = (ioc.context or {}).get("internetdb", {})
        epss = (ioc.context or {}).get("epss", {})
        iocs.append({
            "id": str(ioc.id),
            "value": ioc.value,
            "ioc_type": ioc.ioc_type,
            "risk_score": ioc.risk_score,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "sighting_count": ioc.sighting_count,
            "tags": ioc.tags or [],
            "geo": ioc.geo or [],
            "source_names": ioc.source_names or [],
            "relationship": r.relationship,
            # IPinfo
            "country_code": ioc.country_code,
            "country": ioc.country,
            "asn": ioc.asn,
            "as_name": ioc.as_name,
            # InternetDB
            "ports": internetdb.get("ports", []),
            "vulns": internetdb.get("vulns", []),
            "cpes": internetdb.get("cpes", []),
            "hostnames": internetdb.get("hostnames", []),
            "internetdb_tags": internetdb.get("tags", []),
            # EPSS
            "epss_score": epss.get("score"),
            "epss_percentile": epss.get("percentile"),
        })

    await set_cached(ck, iocs, ttl=120)
    return iocs
