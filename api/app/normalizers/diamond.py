"""Diamond Model vertex extraction from intelligence items.

Maps enriched NewsItem / intel fields to the four Diamond Model vertices:
  - Adversary   (threat_actors)
  - Capability   (malware_families, tactics_techniques, tools)
  - Infrastructure (IOC indicators — IPs, domains, URLs)
  - Victim       (targeted_sectors, targeted_regions, impacted_assets)

Returns structured dicts suitable for the ``relationships`` table or
front-end graph visualisation.
"""

from __future__ import annotations

import re

# Regex to extract primary actor name before aliases in parens
_ACTOR_PRIMARY_RE = re.compile(r"^([^(]+)")

# ── Vertex type constants ────────────────────────────────
ADVERSARY = "adversary"
CAPABILITY = "capability"
INFRASTRUCTURE = "infrastructure"
VICTIM = "victim"


def parse_actor_name(raw: str) -> tuple[str, list[str]]:
    """Parse ``"APT29 (Cozy Bear / Midnight Blizzard)"`` into (primary, aliases).

    Returns:
        (primary_name, [alias1, alias2, ...])
    """
    m = _ACTOR_PRIMARY_RE.match(raw)
    primary = m.group(1).strip() if m else raw.strip()

    aliases: list[str] = []
    paren_start = raw.find("(")
    paren_end = raw.rfind(")")
    if paren_start != -1 and paren_end > paren_start:
        alias_str = raw[paren_start + 1 : paren_end]
        aliases = [a.strip() for a in alias_str.split("/") if a.strip()]

    return primary, aliases


def extract_vertices(item: dict) -> dict[str, list[dict]]:
    """Extract Diamond Model vertices from a news/intel item dict.

    Args:
        item: Dict with NewsItem-like keys (threat_actors, malware_families,
              tactics_techniques, targeted_sectors, targeted_regions,
              impacted_assets, ioc_summary, initial_access_vector).

    Returns:
        Dict keyed by vertex type, each containing a list of vertex dicts::

            {
                "adversary": [{"name": "APT29", "aliases": [...], "raw": ...}],
                "capability": [{"name": "Cobalt Strike", "subtype": "malware"}, ...],
                "infrastructure": [{"value": "1.2.3.4", "ioc_type": "ip"}, ...],
                "victim": [{"name": "Financial Services", "subtype": "sector"}, ...],
            }
    """
    result: dict[str, list[dict]] = {
        ADVERSARY: [],
        CAPABILITY: [],
        INFRASTRUCTURE: [],
        VICTIM: [],
    }

    # ── Adversary ────────────────────────────────────────
    for actor_raw in item.get("threat_actors") or []:
        primary, aliases = parse_actor_name(str(actor_raw))
        if primary:
            result[ADVERSARY].append({
                "name": primary,
                "aliases": aliases,
                "raw": actor_raw,
            })

    # ── Capability ───────────────────────────────────────
    for malware in item.get("malware_families") or []:
        result[CAPABILITY].append({"name": str(malware), "subtype": "malware"})

    for tt in item.get("tactics_techniques") or []:
        result[CAPABILITY].append({"name": str(tt), "subtype": "technique"})

    if item.get("initial_access_vector"):
        result[CAPABILITY].append({
            "name": item["initial_access_vector"],
            "subtype": "initial_access",
        })

    for pe in item.get("post_exploitation") or []:
        result[CAPABILITY].append({"name": str(pe), "subtype": "post_exploitation"})

    # ── Infrastructure ───────────────────────────────────
    ioc_summary = item.get("ioc_summary") or {}
    for ioc_type, values in ioc_summary.items():
        if isinstance(values, list):
            for v in values:
                result[INFRASTRUCTURE].append({
                    "value": str(v),
                    "ioc_type": ioc_type,
                })

    # ── Victim ───────────────────────────────────────────
    for sector in item.get("targeted_sectors") or []:
        result[VICTIM].append({"name": str(sector), "subtype": "sector"})

    for region in item.get("targeted_regions") or []:
        result[VICTIM].append({"name": str(region), "subtype": "region"})

    for asset in item.get("impacted_assets") or []:
        result[VICTIM].append({"name": str(asset), "subtype": "asset"})

    return result


def build_diamond_edges(
    vertices: dict[str, list[dict]],
    source_id: str,
) -> list[dict]:
    """Build relationship edges from Diamond Model vertices.

    Returns a list of relationship dicts ready for ``Relationship`` table
    insertion. Each edge connects two vertices through the source intel item.

    Edge patterns:
        adversary  → uses     → capability
        adversary  → controls → infrastructure
        adversary  → targets  → victim
        capability → exploits → infrastructure
    """
    edges: list[dict] = []

    adversaries = vertices.get(ADVERSARY, [])
    capabilities = vertices.get(CAPABILITY, [])
    infrastructures = vertices.get(INFRASTRUCTURE, [])
    victims = vertices.get(VICTIM, [])

    for adv in adversaries:
        for cap in capabilities:
            edges.append({
                "source_id": adv["name"],
                "source_type": "actor",
                "target_id": cap["name"],
                "target_type": cap.get("subtype", "capability"),
                "relationship_type": "uses",
                "meta": {"intel_id": source_id},
            })

        for infra in infrastructures:
            edges.append({
                "source_id": adv["name"],
                "source_type": "actor",
                "target_id": infra["value"],
                "target_type": "ioc",
                "relationship_type": "controls",
                "meta": {"intel_id": source_id, "ioc_type": infra.get("ioc_type")},
            })

        for vic in victims:
            edges.append({
                "source_id": adv["name"],
                "source_type": "actor",
                "target_id": vic["name"],
                "target_type": vic.get("subtype", "victim"),
                "relationship_type": "targets",
                "meta": {"intel_id": source_id},
            })

    # Capability → Infrastructure (e.g., malware C2 to IP)
    for cap in capabilities:
        if cap.get("subtype") == "malware":
            for infra in infrastructures:
                edges.append({
                    "source_id": cap["name"],
                    "source_type": "malware",
                    "target_id": infra["value"],
                    "target_type": "ioc",
                    "relationship_type": "communicates-with",
                    "meta": {"intel_id": source_id, "ioc_type": infra.get("ioc_type")},
                })

    return edges
