"""Graph / Relationship service — builds and queries entity relationship graphs.

Discovers implicit relationships between intel items by analysing shared IOCs,
CVEs, tags, ATT&CK techniques, and text similarity.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.models import (
    IntelItem,
    IOC,
    IntelIOCLink,
    IntelAttackLink,
    AttackTechnique,
    Relationship,
)

logger = get_logger(__name__)

# ── Relationship types ────────────────────────────────────
REL_SHARES_IOC = "shares-ioc"
REL_SHARES_CVE = "shares-cve"
REL_SHARES_TECHNIQUE = "shares-technique"
REL_INDICATES = "indicates"      # intel → ioc
REL_USES = "uses"                # intel → technique
REL_EXPLOITS = "exploits"        # intel → cve (via cve_ids)
REL_CO_OCCURS = "co-occurs"      # intel ↔ intel (same source + time window)

ENTITY_INTEL = "intel"
ENTITY_IOC = "ioc"
ENTITY_TECHNIQUE = "technique"
ENTITY_CVE = "cve"


# ── Sync helpers (for RQ worker) ─────────────────────────

def build_relationships_batch(session: Session, batch_size: int = 200) -> dict:
    """Discover and store implicit relationships for a batch of intel items.

    Called by the scheduled worker task.  Works in sync mode for RQ compatibility.
    """
    from sqlalchemy import exists

    stats = {"ioc_links": 0, "cve_links": 0, "technique_links": 0, "intel_intel": 0}

    # 1. IOC-based: intel items that share the same IOC
    stats["ioc_links"] = _build_shared_ioc_relationships(session, batch_size)

    # 2. CVE-based: intel items that share the same CVE
    stats["cve_links"] = _build_shared_cve_relationships(session, batch_size)

    # 3. Technique-based: intel items that share the same ATT&CK technique
    stats["technique_links"] = _build_shared_technique_relationships(session, batch_size)

    # 4. Direct intel→IOC edges (from intel_ioc_links, for graph display)
    stats["intel_ioc"] = _build_intel_ioc_edges(session, batch_size)

    session.commit()
    return stats


def _upsert_relationship(
    session: Session,
    source_id: str,
    source_type: str,
    target_id: str,
    target_type: str,
    relationship_type: str,
    confidence: int = 50,
    metadata: dict | None = None,
) -> bool:
    """Insert or update a relationship edge. Returns True if new."""
    stmt = pg_insert(Relationship).values(
        source_id=source_id,
        source_type=source_type,
        target_id=target_id,
        target_type=target_type,
        relationship_type=relationship_type,
        confidence=confidence,
        auto_generated=True,
        meta=metadata or {},
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["source_id", "source_type", "target_id", "target_type", "relationship_type"],
        set_={
            "last_seen": func.now(),
            "confidence": stmt.excluded.confidence,
        },
    )
    result = session.execute(stmt)
    return result.rowcount > 0


def _build_shared_ioc_relationships(session: Session, limit: int) -> int:
    """Find intel pairs that share the same IOC and create edges."""
    # Query: pairs of intel items linked to the same IOC
    a = IntelIOCLink.__table__.alias("a")
    b = IntelIOCLink.__table__.alias("b")

    stmt = (
        select(
            a.c.intel_id.label("src_id"),
            b.c.intel_id.label("tgt_id"),
            func.count().label("shared_count"),
        )
        .select_from(a.join(b, a.c.ioc_id == b.c.ioc_id))
        .where(a.c.intel_id < b.c.intel_id)  # avoid duplicates and self-links
        .group_by(a.c.intel_id, b.c.intel_id)
        .having(func.count() >= 1)
        .order_by(func.count().desc())
        .limit(limit)
    )

    rows = session.execute(stmt).all()
    count = 0
    for row in rows:
        conf = min(90, 30 + row.shared_count * 15)  # more shared IOCs = higher confidence
        if _upsert_relationship(
            session,
            str(row.src_id), ENTITY_INTEL,
            str(row.tgt_id), ENTITY_INTEL,
            REL_SHARES_IOC,
            confidence=conf,
            metadata={"shared_ioc_count": row.shared_count},
        ):
            count += 1
    return count


def _build_shared_cve_relationships(session: Session, limit: int) -> int:
    """Find intel pairs that share CVE IDs (via the cve_ids array overlap)."""
    # Use PostgreSQL array overlap operator &&
    a = IntelItem.__table__.alias("a")
    b = IntelItem.__table__.alias("b")

    stmt = text("""
        SELECT a.id::text AS src_id, b.id::text AS tgt_id,
               array_length(
                 ARRAY(SELECT unnest(a.cve_ids) INTERSECT SELECT unnest(b.cve_ids)), 1
               ) AS shared_count
        FROM intel_items a
        JOIN intel_items b ON a.cve_ids && b.cve_ids AND a.id < b.id
        WHERE array_length(a.cve_ids, 1) > 0
          AND array_length(b.cve_ids, 1) > 0
        ORDER BY shared_count DESC
        LIMIT :lim
    """)

    rows = session.execute(stmt, {"lim": limit}).all()
    count = 0
    for row in rows:
        conf = min(95, 40 + (row.shared_count or 1) * 20)
        if _upsert_relationship(
            session,
            row.src_id, ENTITY_INTEL,
            row.tgt_id, ENTITY_INTEL,
            REL_SHARES_CVE,
            confidence=conf,
            metadata={"shared_cve_count": row.shared_count or 1},
        ):
            count += 1
    return count


def _build_shared_technique_relationships(session: Session, limit: int) -> int:
    """Find intel pairs that share the same ATT&CK technique."""
    a = IntelAttackLink.__table__.alias("a")
    b = IntelAttackLink.__table__.alias("b")

    stmt = (
        select(
            a.c.intel_id.label("src_id"),
            b.c.intel_id.label("tgt_id"),
            func.count().label("shared_count"),
        )
        .select_from(a.join(b, a.c.technique_id == b.c.technique_id))
        .where(a.c.intel_id < b.c.intel_id)
        .group_by(a.c.intel_id, b.c.intel_id)
        .having(func.count() >= 2)  # at least 2 shared techniques = meaningful
        .order_by(func.count().desc())
        .limit(limit)
    )

    rows = session.execute(stmt).all()
    count = 0
    for row in rows:
        conf = min(85, 25 + row.shared_count * 10)
        if _upsert_relationship(
            session,
            str(row.src_id), ENTITY_INTEL,
            str(row.tgt_id), ENTITY_INTEL,
            REL_SHARES_TECHNIQUE,
            confidence=conf,
            metadata={"shared_technique_count": row.shared_count},
        ):
            count += 1
    return count


def _build_intel_ioc_edges(session: Session, limit: int) -> int:
    """Create direct intel ➝ IOC edges from the existing link table."""
    stmt = (
        select(
            IntelIOCLink.intel_id,
            IntelIOCLink.ioc_id,
            IOC.value.label("ioc_value"),
            IOC.ioc_type.label("ioc_type"),
        )
        .join(IOC, IOC.id == IntelIOCLink.ioc_id)
        .limit(limit)
    )

    rows = session.execute(stmt).all()
    count = 0
    for row in rows:
        if _upsert_relationship(
            session,
            str(row.intel_id), ENTITY_INTEL,
            str(row.ioc_id), ENTITY_IOC,
            REL_INDICATES,
            confidence=70,
            metadata={"ioc_value": row.ioc_value, "ioc_type": row.ioc_type},
        ):
            count += 1
    return count


# ── Async query helpers (for API routes) ─────────────────

async def get_entity_graph(
    db: AsyncSession,
    entity_id: str,
    entity_type: str = "intel",
    depth: int = 1,
    limit: int = 50,
) -> dict:
    """Get the graph neighbourhood around an entity.

    Returns nodes and edges for visualization.
    """
    visited_ids: set[str] = set()
    all_nodes: list[dict] = []
    all_edges: list[dict] = []

    # BFS traversal up to `depth` hops
    frontier = [(entity_id, entity_type)]

    for _hop in range(depth):
        if not frontier:
            break

        next_frontier: list[tuple[str, str]] = []

        for eid, etype in frontier:
            node_key = f"{etype}:{eid}"
            if node_key in visited_ids:
                continue
            visited_ids.add(node_key)

            # Fetch relationships where this entity is source or target
            stmt = (
                select(Relationship)
                .where(
                    or_(
                        and_(Relationship.source_id == eid, Relationship.source_type == etype),
                        and_(Relationship.target_id == eid, Relationship.target_type == etype),
                    )
                )
                .order_by(Relationship.confidence.desc())
                .limit(limit)
            )
            result = await db.execute(stmt)
            rels = result.scalars().all()

            for rel in rels:
                # Add edge
                all_edges.append({
                    "id": str(rel.id),
                    "source": f"{rel.source_type}:{rel.source_id}",
                    "target": f"{rel.target_type}:{rel.target_id}",
                    "type": rel.relationship_type,
                    "confidence": rel.confidence,
                    "first_seen": rel.first_seen.isoformat() if rel.first_seen else None,
                    "last_seen": rel.last_seen.isoformat() if rel.last_seen else None,
                    "metadata": rel.meta or {},
                })

                # Determine the other end
                if rel.source_id == eid and rel.source_type == etype:
                    other_id, other_type = rel.target_id, rel.target_type
                else:
                    other_id, other_type = rel.source_id, rel.source_type

                other_key = f"{other_type}:{other_id}"
                if other_key not in visited_ids:
                    next_frontier.append((other_id, other_type))

        frontier = next_frontier

    # Collect unique node IDs from edges and resolve their labels
    node_keys: set[str] = set()
    node_keys.add(f"{entity_type}:{entity_id}")
    for e in all_edges:
        node_keys.add(e["source"])
        node_keys.add(e["target"])

    for nk in node_keys:
        ntype, nid = nk.split(":", 1)
        node = await _resolve_node(db, nid, ntype)
        if node:
            all_nodes.append(node)

    # Deduplicate edges
    seen_edges: set[str] = set()
    unique_edges = []
    for e in all_edges:
        edge_key = f"{e['source']}|{e['target']}|{e['type']}"
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            unique_edges.append(e)

    return {
        "nodes": all_nodes,
        "edges": unique_edges,
        "center": f"{entity_type}:{entity_id}",
        "total_nodes": len(all_nodes),
        "total_edges": len(unique_edges),
    }


async def get_related_intel(
    db: AsyncSession,
    intel_id: str,
    limit: int = 20,
) -> list[dict]:
    """Get intel items related to a given intel item, ranked by confidence."""
    stmt = (
        select(
            Relationship.target_id,
            Relationship.relationship_type,
            Relationship.confidence,
            Relationship.meta,
            Relationship.first_seen,
        )
        .where(
            Relationship.source_type == ENTITY_INTEL,
            Relationship.target_type == ENTITY_INTEL,
            Relationship.source_id == intel_id,
        )
        .order_by(Relationship.confidence.desc())
        .limit(limit)
    )

    result = await db.execute(stmt)
    outgoing = result.all()

    # Also check reverse direction
    stmt2 = (
        select(
            Relationship.source_id.label("target_id"),
            Relationship.relationship_type,
            Relationship.confidence,
            Relationship.meta,
            Relationship.first_seen,
        )
        .where(
            Relationship.source_type == ENTITY_INTEL,
            Relationship.target_type == ENTITY_INTEL,
            Relationship.target_id == intel_id,
        )
        .order_by(Relationship.confidence.desc())
        .limit(limit)
    )
    result2 = await db.execute(stmt2)
    incoming = result2.all()

    # Merge and dedupe
    seen: set[str] = set()
    related = []
    for row in list(outgoing) + list(incoming):
        rid = str(row.target_id)
        if rid in seen or rid == intel_id:
            continue
        seen.add(rid)

        # Fetch the related intel item details
        item_result = await db.execute(
            select(IntelItem).where(IntelItem.id == uuid.UUID(rid)).limit(1)
        )
        item = item_result.scalar_one_or_none()
        if item:
            related.append({
                "id": str(item.id),
                "title": item.title,
                "severity": item.severity,
                "risk_score": item.risk_score,
                "source_name": item.source_name,
                "feed_type": item.feed_type,
                "ingested_at": item.ingested_at.isoformat(),
                "relationship_type": row.relationship_type,
                "confidence": row.confidence,
                "meta": row.meta or {},
            })

    # Sort by confidence desc
    related.sort(key=lambda x: x["confidence"], reverse=True)
    return related[:limit]


async def _resolve_node(db: AsyncSession, node_id: str, node_type: str) -> dict | None:
    """Fetch minimal info for a graph node."""
    if node_type == ENTITY_INTEL:
        try:
            result = await db.execute(
                select(
                    IntelItem.id, IntelItem.title, IntelItem.severity,
                    IntelItem.risk_score, IntelItem.source_name, IntelItem.feed_type,
                ).where(IntelItem.id == uuid.UUID(node_id)).limit(1)
            )
            row = result.one_or_none()
            if row:
                return {
                    "id": f"intel:{node_id}",
                    "type": "intel",
                    "label": row.title[:60] if row.title else node_id[:12],
                    "severity": row.severity,
                    "risk_score": row.risk_score,
                    "source": row.source_name,
                    "feed_type": row.feed_type,
                }
        except Exception:
            pass

    elif node_type == ENTITY_IOC:
        try:
            result = await db.execute(
                select(IOC.id, IOC.value, IOC.ioc_type, IOC.risk_score)
                .where(IOC.id == uuid.UUID(node_id)).limit(1)
            )
            row = result.one_or_none()
            if row:
                return {
                    "id": f"ioc:{node_id}",
                    "type": "ioc",
                    "label": row.value[:40],
                    "ioc_type": row.ioc_type,
                    "risk_score": row.risk_score,
                }
        except Exception:
            pass

    elif node_type == ENTITY_TECHNIQUE:
        result = await db.execute(
            select(AttackTechnique.id, AttackTechnique.name, AttackTechnique.tactic)
            .where(AttackTechnique.id == node_id).limit(1)
        )
        row = result.one_or_none()
        if row:
            return {
                "id": f"technique:{node_id}",
                "type": "technique",
                "label": f"{row.id} {row.name}",
                "tactic": row.tactic,
            }

    elif node_type == ENTITY_CVE:
        return {
            "id": f"cve:{node_id}",
            "type": "cve",
            "label": node_id,
        }

    return {"id": f"{node_type}:{node_id}", "type": node_type, "label": node_id[:30]}


async def get_graph_stats(db: AsyncSession) -> dict:
    """Get aggregate stats about the relationship graph."""
    total = await db.execute(select(func.count()).select_from(Relationship))
    by_type = await db.execute(
        select(Relationship.relationship_type, func.count())
        .group_by(Relationship.relationship_type)
    )
    avg_conf = await db.execute(select(func.avg(Relationship.confidence)).select_from(Relationship))

    return {
        "total_relationships": total.scalar() or 0,
        "by_type": {r[0]: r[1] for r in by_type.all()},
        "avg_confidence": round(float(avg_conf.scalar() or 0), 1),
    }
