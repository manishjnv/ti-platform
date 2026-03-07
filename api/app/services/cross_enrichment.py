"""Cross-enrichment service — links news intel across all platform entities.

Powers:
  - Intel item → campaign/actor badges (via shared CVEs/products)
  - IOC → campaign membership (via news article mentions)
  - Technique → active campaign usage (from news tactics_techniques)
  - Dashboard → active campaigns, top actors, sector threats
  - Threat velocity tracking (article mention acceleration)
  - Org profile personalized exposure scoring
  - Detection rule library aggregation
  - Auto threat briefing data collection
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text, literal_column, case as sa_case
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.redis import cache_key, get_cached, set_cached

logger = get_logger(__name__)


# ──────────────────────────────────────────────────────────
# 1. DASHBOARD ENRICHMENT — Active campaigns, actors, sectors
# ──────────────────────────────────────────────────────────

async def get_active_campaigns(db: AsyncSession, days: int = 7, limit: int = 10) -> list[dict]:
    """Top active threat campaigns by source article count in the given window."""
    q = text("""
        SELECT tc.actor_name, tc.campaign_name, tc.severity,
               tc.source_count, tc.targeted_sectors, tc.targeted_regions,
               tc.malware_used, tc.techniques_used, tc.cves_exploited,
               tc.first_seen, tc.last_seen, tc.id::text
        FROM intel_threat_campaigns tc
        WHERE tc.is_false_positive = FALSE
          AND tc.last_seen >= NOW() - MAKE_INTERVAL(days => :days)
        ORDER BY tc.source_count DESC, tc.last_seen DESC
        LIMIT :lim
    """)
    rows = (await db.execute(q, {"days": days, "lim": limit})).mappings().all()
    return [dict(r) for r in rows]


async def get_top_threat_actors(db: AsyncSession, days: int = 30, limit: int = 10) -> list[dict]:
    """Most mentioned threat actors across news articles."""
    q = text("""
        SELECT actor, COUNT(*) AS mention_count,
               ARRAY_AGG(DISTINCT n.category) AS categories,
               MAX(n.published_at) AS last_seen
        FROM news_items n, UNNEST(n.threat_actors) AS actor
        WHERE n.ai_enriched = TRUE
          AND n.published_at >= NOW() - MAKE_INTERVAL(days => :days)
        GROUP BY actor
        ORDER BY mention_count DESC
        LIMIT :lim
    """)
    rows = (await db.execute(q, {"days": days, "lim": limit})).mappings().all()
    return [dict(r) for r in rows]


async def get_sector_threat_map(db: AsyncSession, days: int = 30) -> list[dict]:
    """Sectors under active threat with campaign counts."""
    q = text("""
        SELECT sector, COUNT(DISTINCT tc.id) AS campaign_count,
               ARRAY_AGG(DISTINCT tc.actor_name ORDER BY tc.actor_name) AS actors,
               MAX(tc.severity) AS max_severity
        FROM intel_threat_campaigns tc,
             UNNEST(tc.targeted_sectors) AS sector
        WHERE tc.is_false_positive = FALSE
          AND tc.last_seen >= NOW() - MAKE_INTERVAL(days => :days)
        GROUP BY sector
        ORDER BY campaign_count DESC
        LIMIT 20
    """)
    rows = (await db.execute(q, {"days": days})).mappings().all()
    return [dict(r) for r in rows]


async def get_trending_cves(db: AsyncSession, days: int = 7, limit: int = 10) -> list[dict]:
    """CVEs appearing in most news articles this week."""
    q = text("""
        SELECT cve, COUNT(*) AS article_count,
               BOOL_OR(n.category = 'exploited_vulnerabilities') AS actively_exploited,
               MAX(n.published_at) AS last_mentioned,
               ARRAY_AGG(DISTINCT actor) FILTER (WHERE actor IS NOT NULL) AS related_actors
        FROM news_items n,
             UNNEST(n.cves) AS cve
             LEFT JOIN LATERAL UNNEST(n.threat_actors) AS actor ON TRUE
        WHERE n.ai_enriched = TRUE
          AND n.published_at >= NOW() - MAKE_INTERVAL(days => :days)
          AND cve ~ '^CVE-'
        GROUP BY cve
        ORDER BY article_count DESC
        LIMIT :lim
    """)
    rows = (await db.execute(q, {"days": days, "lim": limit})).mappings().all()
    return [dict(r) for r in rows]


async def get_campaign_activity_trend(db: AsyncSession, days: int = 30) -> list[dict]:
    """Daily count of new/active campaigns over the period."""
    q = text("""
        SELECT d::date AS date, COUNT(DISTINCT tc.id) AS active_campaigns
        FROM generate_series(
            (NOW() - MAKE_INTERVAL(days => :days))::date,
            NOW()::date,
            '1 day'::interval
        ) AS d
        LEFT JOIN intel_threat_campaigns tc
            ON tc.last_seen::date >= d::date
           AND tc.first_seen::date <= d::date
           AND tc.is_false_positive = FALSE
        GROUP BY d::date
        ORDER BY d::date
    """)
    rows = (await db.execute(q, {"days": days})).mappings().all()
    return [{"date": str(r["date"]), "count": r["active_campaigns"]} for r in rows]


async def get_dashboard_enrichment(db: AsyncSession) -> dict:
    """Full dashboard enrichment data bundle."""
    ck = cache_key("dashboard_enrichment")
    cached = await get_cached(ck)
    if cached:
        return cached

    data = {
        "active_campaigns": await get_active_campaigns(db),
        "top_actors": await get_top_threat_actors(db),
        "sector_threats": await get_sector_threat_map(db),
        "trending_cves": await get_trending_cves(db),
        "campaign_trend": await get_campaign_activity_trend(db),
    }
    await set_cached(ck, data, ttl=120)
    return data


# ──────────────────────────────────────────────────────────
# 2. INTEL ITEM CROSS-LINKING — Campaign/actor badges
# ──────────────────────────────────────────────────────────

async def get_intel_campaign_context(db: AsyncSession, cve_ids: list[str], products: list[str]) -> dict:
    """For an intel item, find related campaigns and actors via shared CVEs/products."""
    if not cve_ids and not products:
        return {"campaigns": [], "actors": [], "news_articles": []}

    params: dict = {}
    conditions = []

    if cve_ids:
        conditions.append("n.cves && :cves")
        params["cves"] = cve_ids

    if products:
        conditions.append("n.vulnerable_products && :products")
        params["products"] = products

    where = " OR ".join(conditions)
    q = text(f"""
        SELECT DISTINCT n.id::text, n.headline, n.source, n.source_url,
               n.campaign_name, n.threat_actors, n.targeted_sectors,
               n.published_at, n.category
        FROM news_items n
        WHERE n.ai_enriched = TRUE AND ({where})
        ORDER BY n.published_at DESC
        LIMIT 20
    """)
    rows = (await db.execute(q, params)).mappings().all()

    campaigns = set()
    actors = set()
    articles = []
    for r in rows:
        if r["campaign_name"]:
            campaigns.add(r["campaign_name"])
        for a in (r["threat_actors"] or []):
            actors.add(a)
        articles.append({
            "id": r["id"], "headline": r["headline"],
            "source": r["source"], "source_url": r["source_url"],
            "campaign_name": r["campaign_name"],
            "published_at": r["published_at"].isoformat() if r["published_at"] else None,
        })

    return {
        "campaigns": sorted(campaigns),
        "actors": sorted(actors),
        "news_articles": articles[:10],
    }


async def get_intel_items_enriched(db: AsyncSession, item_ids: list[str]) -> dict[str, dict]:
    """Batch-enrich multiple intel items with campaign/actor context from news.
    Returns a dict mapping item_id → {campaigns:[], actors:[], article_count}.
    """
    if not item_ids:
        return {}

    # Get CVE IDs and products for each intel item
    q = text("""
        SELECT i.id::text, i.cve_ids, i.affected_products
        FROM intel_items i
        WHERE i.id = ANY(:ids::uuid[])
    """)
    rows = (await db.execute(q, {"ids": item_ids})).mappings().all()

    all_cves = set()
    all_products = set()
    item_map = {}
    for r in rows:
        item_map[r["id"]] = {"cves": r["cve_ids"] or [], "products": r["affected_products"] or []}
        all_cves.update(r["cve_ids"] or [])
        all_products.update(r["affected_products"] or [])

    if not all_cves and not all_products:
        return {iid: {"campaigns": [], "actors": [], "article_count": 0} for iid in item_ids}

    # Find news articles matching any of these CVEs/products
    params: dict[str, Any] = {}
    conditions = []
    if all_cves:
        conditions.append("n.cves && :cves")
        params["cves"] = list(all_cves)
    if all_products:
        conditions.append("n.vulnerable_products && :products")
        params["products"] = list(all_products)

    where = " OR ".join(conditions)
    q2 = text(f"""
        SELECT n.cves, n.vulnerable_products, n.campaign_name, n.threat_actors
        FROM news_items n
        WHERE n.ai_enriched = TRUE AND ({where})
    """)
    news_rows = (await db.execute(q2, params)).mappings().all()

    # Map back to each intel item
    result: dict[str, dict] = {}
    for iid, idata in item_map.items():
        campaigns = set()
        actors = set()
        count = 0
        for nr in news_rows:
            nr_cves = set(nr["cves"] or [])
            nr_prods = set(nr["vulnerable_products"] or [])
            if (nr_cves & set(idata["cves"])) or (nr_prods & set(idata["products"])):
                count += 1
                if nr["campaign_name"]:
                    campaigns.add(nr["campaign_name"])
                for a in (nr["threat_actors"] or []):
                    actors.add(a)
        result[iid] = {
            "campaigns": sorted(campaigns)[:5],
            "actors": sorted(actors)[:5],
            "article_count": count,
        }

    # Ensure all requested IDs are represented
    for iid in item_ids:
        if iid not in result:
            result[iid] = {"campaigns": [], "actors": [], "article_count": 0}

    return result


# ──────────────────────────────────────────────────────────
# 3. IOC CROSS-LINKING — Campaign membership
# ──────────────────────────────────────────────────────────

async def get_ioc_campaign_context(db: AsyncSession, ioc_value: str) -> dict:
    """Find campaigns/actors that mention this IOC in their source news articles."""
    q = text("""
        SELECT DISTINCT tc.actor_name, tc.campaign_name, tc.severity,
               tc.targeted_sectors, tc.malware_used
        FROM intel_threat_campaigns tc
        JOIN news_items n ON n.id = ANY(tc.source_news_ids)
        WHERE tc.is_false_positive = FALSE
          AND (
            n.headline ILIKE '%' || :val || '%'
            OR n.raw_content ILIKE '%' || :val || '%'
          )
        LIMIT 10
    """)
    rows = (await db.execute(q, {"val": ioc_value})).mappings().all()
    return {
        "campaigns": [
            {"actor": r["actor_name"], "campaign": r["campaign_name"],
             "severity": r["severity"], "sectors": r["targeted_sectors"],
             "malware": r["malware_used"]}
            for r in rows
        ]
    }


# ──────────────────────────────────────────────────────────
# 4. TECHNIQUE CROSS-LINKING — Active campaign usage heatmap
# ──────────────────────────────────────────────────────────

async def get_technique_campaign_usage(db: AsyncSession, days: int = 30) -> list[dict]:
    """For each ATT&CK technique, count active campaigns and news articles using it."""
    ck = cache_key(f"technique_campaign_usage:{days}")
    cached = await get_cached(ck)
    if cached:
        return cached

    q = text("""
        SELECT technique, COUNT(DISTINCT n.id) AS article_count,
               ARRAY_AGG(DISTINCT n.campaign_name) FILTER (WHERE n.campaign_name IS NOT NULL) AS campaigns,
               ARRAY_AGG(DISTINCT actor) FILTER (WHERE actor IS NOT NULL) AS actors,
               ARRAY_AGG(DISTINCT sector) FILTER (WHERE sector IS NOT NULL) AS sectors
        FROM news_items n,
             UNNEST(n.tactics_techniques) AS technique
             LEFT JOIN LATERAL UNNEST(n.threat_actors) AS actor ON TRUE
             LEFT JOIN LATERAL UNNEST(n.targeted_sectors) AS sector ON TRUE
        WHERE n.ai_enriched = TRUE
          AND n.published_at >= NOW() - MAKE_INTERVAL(days => :days)
        GROUP BY technique
        ORDER BY article_count DESC
    """)
    rows = (await db.execute(q, {"days": days})).mappings().all()
    result = [dict(r) for r in rows]
    await set_cached(ck, result, ttl=300)
    return result


async def get_technique_detail_enrichment(db: AsyncSession, technique_id: str) -> dict:
    """Enrich a specific technique with campaign/actor/sector data from news."""
    q = text("""
        SELECT n.id::text, n.headline, n.source, n.campaign_name,
               n.threat_actors, n.targeted_sectors, n.targeted_regions,
               n.published_at, n.yara_rule IS NOT NULL AS has_yara,
               n.kql_rule IS NOT NULL AS has_kql
        FROM news_items n
        WHERE n.ai_enriched = TRUE
          AND :tid = ANY(n.tactics_techniques)
        ORDER BY n.published_at DESC
        LIMIT 20
    """)
    rows = (await db.execute(q, {"tid": technique_id})).mappings().all()

    campaigns = set()
    actors = set()
    sectors = set()
    detection_available = {"yara": 0, "kql": 0}
    articles = []
    for r in rows:
        if r["campaign_name"]:
            campaigns.add(r["campaign_name"])
        for a in (r["threat_actors"] or []):
            actors.add(a)
        for s in (r["targeted_sectors"] or []):
            sectors.add(s)
        if r["has_yara"]:
            detection_available["yara"] += 1
        if r["has_kql"]:
            detection_available["kql"] += 1
        articles.append({
            "id": r["id"], "headline": r["headline"],
            "source": r["source"], "campaign_name": r["campaign_name"],
            "published_at": r["published_at"].isoformat() if r["published_at"] else None,
        })

    return {
        "campaigns": sorted(campaigns),
        "actors": sorted(actors),
        "sectors": sorted(sectors),
        "article_count": len(rows),
        "detection_rules": detection_available,
        "recent_articles": articles[:10],
    }


# ──────────────────────────────────────────────────────────
# 5. THREAT VELOCITY — Mention acceleration tracking
# ──────────────────────────────────────────────────────────

async def get_threat_velocity(db: AsyncSession, days: int = 14) -> list[dict]:
    """Track entities whose news mention velocity is accelerating.
    CVEs are enriched with product name, published_at, KEV, patch, exploit status."""
    ck = cache_key(f"threat_velocity:{days}")
    cached = await get_cached(ck)
    if cached:
        return cached

    # Compare mentions in the last 3 days vs previous 3 days — CVEs enriched with vuln metadata
    q = text("""
        WITH recent AS (
            SELECT cve, COUNT(*) AS cnt,
                   MAX(n.published_at) AS last_published
            FROM news_items n, UNNEST(n.cves) AS cve
            WHERE n.published_at >= NOW() - INTERVAL '3 days'
              AND n.ai_enriched = TRUE AND cve ~ '^CVE-'
            GROUP BY cve
        ), previous AS (
            SELECT cve, COUNT(*) AS cnt
            FROM news_items n, UNNEST(n.cves) AS cve
            WHERE n.published_at >= NOW() - INTERVAL '7 days'
              AND n.published_at < NOW() - INTERVAL '3 days'
              AND n.ai_enriched = TRUE AND cve ~ '^CVE-'
            GROUP BY cve
        )
        SELECT COALESCE(r.cve, p.cve) AS entity,
               'cve' AS entity_type,
               COALESCE(r.cnt, 0) AS recent_count,
               COALESCE(p.cnt, 0) AS previous_count,
               COALESCE(r.cnt, 0) - COALESCE(p.cnt, 0) AS velocity_change,
               r.last_published AS published_at,
               vp.product_name,
               COALESCE(vp.is_kev, FALSE) AS is_kev,
               COALESCE(vp.patch_available, FALSE) AS patch_available,
               COALESCE(vp.exploit_available, FALSE) AS exploit_available,
               vp.severity AS vuln_severity
        FROM recent r FULL OUTER JOIN previous p ON r.cve = p.cve
        LEFT JOIN LATERAL (
            SELECT product_name, is_kev, patch_available, exploit_available, severity
            FROM intel_vulnerable_products
            WHERE cve_id = COALESCE(r.cve, p.cve)
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT 1
        ) vp ON TRUE
        WHERE COALESCE(r.cnt, 0) > COALESCE(p.cnt, 0)
        ORDER BY velocity_change DESC
        LIMIT 10
    """)
    cve_rows = (await db.execute(q)).mappings().all()

    # Actor velocity — enriched with recent action + target info
    q2 = text("""
        WITH recent AS (
            SELECT actor, COUNT(*) AS cnt,
                   MAX(n.published_at) AS last_published,
                   (ARRAY_AGG(n.headline ORDER BY n.published_at DESC))[1] AS recent_headline,
                   ARRAY_AGG(DISTINCT sector) FILTER (WHERE sector IS NOT NULL) AS targeted_sectors
            FROM news_items n, UNNEST(n.threat_actors) AS actor
                 LEFT JOIN LATERAL UNNEST(n.targeted_sectors) AS sector ON TRUE
            WHERE n.published_at >= NOW() - INTERVAL '3 days'
              AND n.ai_enriched = TRUE
            GROUP BY actor
        ), previous AS (
            SELECT actor, COUNT(*) AS cnt
            FROM news_items n, UNNEST(n.threat_actors) AS actor
            WHERE n.published_at >= NOW() - INTERVAL '7 days'
              AND n.published_at < NOW() - INTERVAL '3 days'
              AND n.ai_enriched = TRUE
            GROUP BY actor
        )
        SELECT COALESCE(r.actor, p.actor) AS entity,
               'actor' AS entity_type,
               COALESCE(r.cnt, 0) AS recent_count,
               COALESCE(p.cnt, 0) AS previous_count,
               COALESCE(r.cnt, 0) - COALESCE(p.cnt, 0) AS velocity_change,
               r.last_published AS published_at,
               r.recent_headline,
               r.targeted_sectors
        FROM recent r FULL OUTER JOIN previous p ON r.actor = p.actor
        WHERE COALESCE(r.cnt, 0) > COALESCE(p.cnt, 0)
        ORDER BY velocity_change DESC
        LIMIT 10
    """)
    actor_rows = (await db.execute(q2)).mappings().all()

    cve_result = []
    for r in cve_rows:
        d = dict(r)
        d["published_at"] = d["published_at"].isoformat() if d.get("published_at") else None
        cve_result.append(d)

    actor_result = []
    for r in actor_rows:
        d = dict(r)
        d["published_at"] = d["published_at"].isoformat() if d.get("published_at") else None
        actor_result.append(d)

    result = cve_result + actor_result
    result.sort(key=lambda x: x["velocity_change"], reverse=True)
    await set_cached(ck, result[:15], ttl=300)
    return result[:15]


# ──────────────────────────────────────────────────────────
# 6. ORG PROFILE — Personalized exposure score
# ──────────────────────────────────────────────────────────

async def get_org_exposure(db: AsyncSession, org_sectors: list[str],
                           org_regions: list[str], org_tech_stack: list[str]) -> dict:
    """Calculate personalized threat exposure for the org profile."""
    ck_parts = f"{','.join(sorted(org_sectors))}:{','.join(sorted(org_regions))}:{','.join(sorted(org_tech_stack))}"
    ck = cache_key(f"org_exposure:{ck_parts}")
    cached = await get_cached(ck)
    if cached:
        return cached

    # Campaigns targeting org's sectors
    sector_filter = "tc.targeted_sectors && :sectors" if org_sectors else "TRUE"
    q = text(f"""
        SELECT tc.id::text, tc.actor_name, tc.campaign_name, tc.severity,
               tc.targeted_sectors, tc.cves_exploited, tc.techniques_used,
               tc.last_seen
        FROM intel_threat_campaigns tc
        WHERE tc.is_false_positive = FALSE
          AND tc.last_seen >= NOW() - INTERVAL '30 days'
          AND {sector_filter}
        ORDER BY tc.source_count DESC
        LIMIT 20
    """)
    params: dict = {}
    if org_sectors:
        params["sectors"] = org_sectors
    campaign_rows = (await db.execute(q, params)).mappings().all()

    # Vulnerable products in org's tech stack
    prod_conditions = []
    for i, tech in enumerate(org_tech_stack[:20]):
        prod_conditions.append(f"vp.product_name ILIKE :t{i}")
        params[f"t{i}"] = f"%{tech}%"

    prod_rows = []
    if prod_conditions:
        q2 = text(f"""
            SELECT vp.product_name, vp.cve_id, vp.severity, vp.cvss_score,
                   vp.is_kev, vp.exploit_available, vp.patch_available
            FROM intel_vulnerable_products vp
            WHERE vp.is_false_positive = FALSE
              AND vp.last_seen >= NOW() - INTERVAL '30 days'
              AND ({' OR '.join(prod_conditions)})
            ORDER BY vp.cvss_score DESC NULLS LAST
            LIMIT 20
        """)
        prod_rows = (await db.execute(q2, params)).mappings().all()

    # Calculate exposure score (0-100)
    score = 0
    critical_campaigns = sum(1 for c in campaign_rows if c["severity"] == "critical")
    high_campaigns = sum(1 for c in campaign_rows if c["severity"] == "high")
    kev_vulns = sum(1 for p in prod_rows if p["is_kev"])
    exploit_vulns = sum(1 for p in prod_rows if p["exploit_available"])

    score += min(30, critical_campaigns * 15 + high_campaigns * 8)  # campaign threat
    score += min(30, kev_vulns * 15 + exploit_vulns * 8)            # vulnerability threat
    score += min(20, len(prod_rows) * 3)                             # exposure breadth
    score += min(20, len(campaign_rows) * 2)                         # targeting frequency
    score = min(100, score)

    result = {
        "exposure_score": score,
        "targeting_campaigns": [dict(r) for r in campaign_rows[:10]],
        "vulnerable_products": [dict(r) for r in prod_rows[:10]],
        "stats": {
            "active_campaigns": len(campaign_rows),
            "critical_campaigns": critical_campaigns,
            "vulnerable_products": len(prod_rows),
            "kev_count": kev_vulns,
            "exploitable_count": exploit_vulns,
        },
    }
    await set_cached(ck, result, ttl=300)
    return result


# ──────────────────────────────────────────────────────────
# 7. DETECTION RULE LIBRARY
# ──────────────────────────────────────────────────────────

async def get_detection_rules(db: AsyncSession, rule_type: str | None = None,
                              severity: str | None = None,
                              campaign: str | None = None, limit: int = 100) -> list[dict]:
    """Query detection rules from the library."""
    conditions = []
    params: dict = {}

    if rule_type:
        conditions.append("dr.rule_type = :rt")
        params["rt"] = rule_type
    if severity:
        conditions.append("dr.severity = :sev")
        params["sev"] = severity
    if campaign:
        conditions.append("dr.campaign_name ILIKE :camp")
        params["camp"] = f"%{campaign}%"

    where = " AND ".join(conditions) if conditions else "TRUE"
    q = text(f"""
        SELECT dr.id::text, dr.rule_type, dr.name, dr.content,
               dr.campaign_name, dr.technique_ids, dr.cve_ids,
               dr.severity, dr.quality_score, dr.created_at,
               n.headline AS source_headline, n.source AS source_name
        FROM detection_rules dr
        LEFT JOIN news_items n ON n.id = dr.source_news_id
        WHERE {where}
        ORDER BY dr.created_at DESC
        LIMIT :lim
    """)
    params["lim"] = limit
    rows = (await db.execute(q, params)).mappings().all()
    return [dict(r) for r in rows]


async def get_detection_coverage(db: AsyncSession) -> dict:
    """Detection rule coverage stats."""
    q = text("""
        SELECT
            COUNT(*) AS total_rules,
            COUNT(*) FILTER (WHERE rule_type = 'yara') AS yara_count,
            COUNT(*) FILTER (WHERE rule_type = 'kql') AS kql_count,
            COUNT(*) FILTER (WHERE rule_type = 'sigma') AS sigma_count,
            COUNT(DISTINCT campaign_name) FILTER (WHERE campaign_name IS NOT NULL) AS campaigns_covered,
            COUNT(DISTINCT tid) AS techniques_covered
        FROM detection_rules dr, UNNEST(COALESCE(NULLIF(dr.technique_ids, '{}'), ARRAY['__none__'])) AS tid
    """)
    row = (await db.execute(q)).mappings().first()
    if not row:
        return {"total_rules": 0, "yara_count": 0, "kql_count": 0, "sigma_count": 0,
                "campaigns_covered": 0, "techniques_covered": 0}
    return dict(row)


async def sync_detection_rules(db: AsyncSession) -> int:
    """Extract YARA/KQL rules from news_items and insert into detection_rules table."""
    # Find news items with rules not yet in detection_rules
    q = text("""
        INSERT INTO detection_rules (rule_type, name, content, source_news_id, campaign_name,
                                     technique_ids, cve_ids, severity)
        SELECT 'yara', 'YARA: ' || LEFT(n.headline, 280), n.yara_rule, n.id,
               n.campaign_name, n.tactics_techniques, n.cves,
               COALESCE(n.recommended_priority, 'medium')
        FROM news_items n
        WHERE n.yara_rule IS NOT NULL AND n.yara_rule != ''
          AND NOT EXISTS (
            SELECT 1 FROM detection_rules dr
            WHERE dr.source_news_id = n.id AND dr.rule_type = 'yara'
          )
        ON CONFLICT DO NOTHING
    """)
    r1 = await db.execute(q)

    q2 = text("""
        INSERT INTO detection_rules (rule_type, name, content, source_news_id, campaign_name,
                                     technique_ids, cve_ids, severity)
        SELECT 'kql', 'KQL: ' || LEFT(n.headline, 280), n.kql_rule, n.id,
               n.campaign_name, n.tactics_techniques, n.cves,
               COALESCE(n.recommended_priority, 'medium')
        FROM news_items n
        WHERE n.kql_rule IS NOT NULL AND n.kql_rule != ''
          AND NOT EXISTS (
            SELECT 1 FROM detection_rules dr
            WHERE dr.source_news_id = n.id AND dr.rule_type = 'kql'
          )
        ON CONFLICT DO NOTHING
    """)
    r2 = await db.execute(q2)
    await db.commit()
    return (r1.rowcount or 0) + (r2.rowcount or 0)


# ──────────────────────────────────────────────────────────
# 8. THREAT BRIEFING DATA COLLECTION
# ──────────────────────────────────────────────────────────

async def collect_briefing_data(db: AsyncSession, days: int = 7) -> dict:
    """Collect all data needed for AI threat briefing generation."""
    campaigns = await get_active_campaigns(db, days=days, limit=20)
    actors = await get_top_threat_actors(db, days=days, limit=15)
    sectors = await get_sector_threat_map(db, days=days)
    trending = await get_trending_cves(db, days=days, limit=15)
    velocity = await get_threat_velocity(db, days=days)

    # Stats
    q = text("""
        SELECT
            COUNT(DISTINCT tc.id) AS new_campaigns,
            COUNT(DISTINCT cve) AS new_cves,
            (SELECT COUNT(*) FROM news_items WHERE published_at >= NOW() - MAKE_INTERVAL(days => :days) AND ai_enriched = TRUE) AS articles_processed
        FROM intel_threat_campaigns tc
        FULL OUTER JOIN (
            SELECT UNNEST(n.cves) AS cve
            FROM news_items n
            WHERE n.published_at >= NOW() - MAKE_INTERVAL(days => :days) AND n.ai_enriched = TRUE
        ) cves ON TRUE
        WHERE tc.first_seen >= NOW() - MAKE_INTERVAL(days => :days)
    """)
    stats_row = (await db.execute(q, {"days": days})).mappings().first()

    # KEVs added
    q_kev = text("""
        SELECT COUNT(*) AS kev_added
        FROM intel_vulnerable_products
        WHERE is_kev = TRUE AND first_seen >= NOW() - MAKE_INTERVAL(days => :days)
    """)
    kev_row = (await db.execute(q_kev, {"days": days})).mappings().first()

    return {
        "period_days": days,
        "campaigns": campaigns,
        "actors": actors,
        "sector_threats": sectors,
        "trending_cves": trending,
        "velocity": velocity,
        "stats": {
            "new_campaigns": stats_row["new_campaigns"] if stats_row else 0,
            "new_cves": stats_row["new_cves"] if stats_row else 0,
            "articles_processed": stats_row["articles_processed"] if stats_row else 0,
            "kev_added": kev_row["kev_added"] if kev_row else 0,
        },
    }
