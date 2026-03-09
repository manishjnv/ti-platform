"""Cross-feed correlation — overlap detection and confidence boosting.

Detects when the same IOC, CVE, threat actor, or malware family appears
across multiple feeds/sources and applies confidence boosting. Also
provides entity overlap analysis for intelligence fusion.
"""

from __future__ import annotations

from collections import defaultdict

# ── Confidence boost per additional corroborating source ──
# Diminishing returns: 1st extra source = +15, 2nd = +10, 3rd = +5, etc.
_CORROBORATION_BOOSTS: list[int] = [15, 10, 5, 3, 2]
MAX_CORROBORATION_BOOST = 35  # sum of above


def corroboration_boost(source_count: int) -> int:
    """Return a confidence boost (0-35) based on how many sources report the same entity.

    Args:
        source_count: Total number of distinct sources/feeds reporting this entity.

    Returns:
        Integer bonus to add to base confidence (0-35).
    """
    if source_count <= 1:
        return 0

    extra = source_count - 1  # First source is baseline
    boost = 0
    for i in range(min(extra, len(_CORROBORATION_BOOSTS))):
        boost += _CORROBORATION_BOOSTS[i]

    return min(boost, MAX_CORROBORATION_BOOST)


def find_cve_overlaps(
    items: list[dict],
    min_sources: int = 2,
) -> dict[str, dict]:
    """Find CVEs that appear across multiple sources/feeds.

    Args:
        items: List of intel item dicts with ``cve_ids`` (list[str])
               and ``source_name`` (str) keys.
        min_sources: Minimum distinct sources for an overlap to be flagged.

    Returns:
        Dict keyed by CVE ID::

            {
                "CVE-2024-1234": {
                    "sources": {"NVD", "KEV", "OTX"},
                    "count": 3,
                    "max_risk": 85,
                    "boost": 25,
                    "item_ids": ["uuid1", "uuid2", ...],
                },
            }
    """
    cve_map: dict[str, dict] = {}

    for item in items:
        source = item.get("source_name", "unknown")
        risk = item.get("risk_score", 0)
        item_id = str(item.get("id", ""))

        for cve in item.get("cve_ids") or item.get("cves") or []:
            cve_upper = str(cve).upper()
            if cve_upper not in cve_map:
                cve_map[cve_upper] = {
                    "sources": set(),
                    "max_risk": 0,
                    "item_ids": [],
                }
            cve_map[cve_upper]["sources"].add(source)
            cve_map[cve_upper]["max_risk"] = max(cve_map[cve_upper]["max_risk"], risk)
            if item_id:
                cve_map[cve_upper]["item_ids"].append(item_id)

    # Filter to overlaps and add computed fields
    result = {}
    for cve, data in cve_map.items():
        if len(data["sources"]) >= min_sources:
            result[cve] = {
                "sources": data["sources"],
                "count": len(data["sources"]),
                "max_risk": data["max_risk"],
                "boost": corroboration_boost(len(data["sources"])),
                "item_ids": data["item_ids"],
            }

    return result


def find_ioc_overlaps(
    items: list[dict],
    min_sources: int = 2,
) -> dict[str, dict]:
    """Find IOC values that appear across multiple sources.

    Args:
        items: List of dicts with ``ioc_summary`` (dict mapping type→list)
               and ``source_name`` (str).
        min_sources: Minimum distinct sources for an overlap.

    Returns:
        Dict keyed by ``"type:value"``::

            {
                "ip:1.2.3.4": {
                    "ioc_type": "ip",
                    "value": "1.2.3.4",
                    "sources": {"AbuseIPDB", "OTX"},
                    "count": 2,
                    "boost": 15,
                },
            }
    """
    ioc_map: dict[str, dict] = {}

    for item in items:
        source = item.get("source_name") or item.get("source", "unknown")
        ioc_summary = item.get("ioc_summary") or {}

        for ioc_type, values in ioc_summary.items():
            if not isinstance(values, list):
                continue
            for val in values:
                key = f"{ioc_type}:{val}"
                if key not in ioc_map:
                    ioc_map[key] = {
                        "ioc_type": ioc_type,
                        "value": str(val),
                        "sources": set(),
                    }
                ioc_map[key]["sources"].add(source)

    result = {}
    for key, data in ioc_map.items():
        if len(data["sources"]) >= min_sources:
            result[key] = {
                **data,
                "count": len(data["sources"]),
                "boost": corroboration_boost(len(data["sources"])),
            }

    return result


def find_actor_overlaps(
    items: list[dict],
    min_sources: int = 2,
) -> dict[str, dict]:
    """Find threat actors mentioned across multiple sources.

    Normalises actor names by stripping alias parenthetical suffixes
    so ``"APT29 (Cozy Bear)"`` and ``"APT29"`` merge correctly.
    """
    actor_map: dict[str, dict] = {}

    for item in items:
        source = item.get("source_name") or item.get("source", "unknown")
        for actor_raw in item.get("threat_actors") or []:
            # Extract primary name before aliases
            primary = str(actor_raw).split("(")[0].strip()
            if not primary:
                continue
            key = primary.lower()
            if key not in actor_map:
                actor_map[key] = {"name": primary, "sources": set()}
            actor_map[key]["sources"].add(source)

    result = {}
    for key, data in actor_map.items():
        if len(data["sources"]) >= min_sources:
            result[key] = {
                **data,
                "count": len(data["sources"]),
                "boost": corroboration_boost(len(data["sources"])),
            }

    return result


def compute_overlap_summary(items: list[dict]) -> dict:
    """Compute a full correlation summary across CVEs, IOCs, and actors.

    Returns:
        Summary dict with counts and top overlapping entities::

            {
                "cve_overlaps": 5,
                "ioc_overlaps": 12,
                "actor_overlaps": 2,
                "top_cves": [...],
                "top_actors": [...],
            }
    """
    cve_overlaps = find_cve_overlaps(items)
    ioc_overlaps = find_ioc_overlaps(items)
    actor_overlaps = find_actor_overlaps(items)

    # Sort by source count descending
    top_cves = sorted(cve_overlaps.values(), key=lambda x: x["count"], reverse=True)[:10]
    top_actors = sorted(actor_overlaps.values(), key=lambda x: x["count"], reverse=True)[:10]

    # Serialise sets for JSON compatibility
    for entry in top_cves:
        entry["sources"] = sorted(entry["sources"])
    for entry in top_actors:
        entry["sources"] = sorted(entry["sources"])

    return {
        "cve_overlaps": len(cve_overlaps),
        "ioc_overlaps": len(ioc_overlaps),
        "actor_overlaps": len(actor_overlaps),
        "top_cves": top_cves,
        "top_actors": top_actors,
    }
