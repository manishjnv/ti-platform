"""API routes for MITRE ATT&CK techniques."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, case, Integer as SAInteger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.middleware.auth import require_viewer
from app.models.models import AttackTechnique, IntelAttackLink, IntelItem, User
from app.schemas import (
    AttackMatrixCell,
    AttackMatrixResponse,
    AttackMatrixTactic,
    AttackTechniqueListResponse,
    AttackTechniqueResponse,
    IntelAttackLinkResponse,
)
from app.services.mitre import TACTIC_ORDER, TACTIC_LABELS

router = APIRouter(prefix="/techniques", tags=["techniques"])


@router.get("", response_model=AttackTechniqueListResponse)
async def list_techniques(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    tactic: str | None = None,
    search: str | None = None,
    has_intel: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
):
    """List ATT&CK techniques with optional filters."""
    ck = cache_key("techniques_list", tactic, search, has_intel, page, page_size)
    cached = await get_cached(ck)
    if cached:
        return cached

    # Base query — only parent techniques by default
    query = select(AttackTechnique)

    if tactic:
        query = query.where(AttackTechnique.tactic == tactic)
    if search:
        query = query.where(
            AttackTechnique.name.ilike(f"%{search}%")
            | AttackTechnique.id.ilike(f"%{search}%")
        )

    # Filter to only techniques with intel hits
    if has_intel:
        hit_ids = (
            select(IntelAttackLink.technique_id)
            .distinct()
            .subquery()
        )
        query = query.where(AttackTechnique.id.in_(select(hit_ids.c.technique_id)))

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Paginate
    query = query.order_by(AttackTechnique.id).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    techniques = list(result.scalars().all())

    # Get intel counts per technique
    technique_ids = [t.id for t in techniques]
    counts: dict[str, int] = {}
    if technique_ids:
        count_stmt = (
            select(IntelAttackLink.technique_id, func.count().label("cnt"))
            .where(IntelAttackLink.technique_id.in_(technique_ids))
            .group_by(IntelAttackLink.technique_id)
        )
        count_result = await db.execute(count_stmt)
        counts = {row.technique_id: row.cnt for row in count_result}

    # Get unique tactics
    tactics_q = select(AttackTechnique.tactic).distinct().order_by(AttackTechnique.tactic)
    tactics_result = await db.execute(tactics_q)
    all_tactics = [r[0] for r in tactics_result]

    items = []
    for t in techniques:
        resp = AttackTechniqueResponse.model_validate(t)
        resp.intel_count = counts.get(t.id, 0)
        items.append(resp)

    response = AttackTechniqueListResponse(
        techniques=items,
        total=total,
        tactics=all_tactics,
    )

    await set_cached(ck, response.model_dump(), ttl=120)
    return response


@router.get("/matrix", response_model=AttackMatrixResponse)
async def get_attack_matrix(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Return ATT&CK matrix heatmap data — techniques grouped by tactic with intel counts."""
    ck = cache_key("attack_matrix")
    cached = await get_cached(ck)
    if cached:
        return cached

    # Get all parent techniques with their intel counts and max risk scores
    stmt = (
        select(
            AttackTechnique.id,
            AttackTechnique.name,
            AttackTechnique.tactic,
            func.count(IntelAttackLink.intel_id).label("count"),
            func.coalesce(func.max(IntelItem.risk_score), 0).label("max_risk"),
        )
        .outerjoin(IntelAttackLink, IntelAttackLink.technique_id == AttackTechnique.id)
        .outerjoin(
            IntelItem,
            (IntelItem.id == IntelAttackLink.intel_id)
            & (IntelItem.ingested_at == IntelAttackLink.intel_ingested_at),
        )
        .where(AttackTechnique.is_subtechnique == False)  # noqa: E712
        .group_by(AttackTechnique.id, AttackTechnique.name, AttackTechnique.tactic)
        .order_by(AttackTechnique.id)
    )

    result = await db.execute(stmt)
    rows = result.all()

    # Group by tactic
    tactic_map: dict[str, list[AttackMatrixCell]] = {}
    total_mapped = 0
    for row in rows:
        cell = AttackMatrixCell(
            id=row.id,
            name=row.name,
            count=row.count,
            max_risk=row.max_risk,
        )
        if row.count > 0:
            total_mapped += 1
        tactic_map.setdefault(row.tactic, []).append(cell)

    # Build ordered tactics list
    tactics = []
    for tactic_key in TACTIC_ORDER:
        if tactic_key in tactic_map:
            tactics.append(
                AttackMatrixTactic(
                    tactic=tactic_key,
                    label=TACTIC_LABELS.get(tactic_key, tactic_key),
                    techniques=tactic_map[tactic_key],
                )
            )

    response = AttackMatrixResponse(
        tactics=tactics,
        total_techniques=len(rows),
        total_mapped=total_mapped,
    )

    await set_cached(ck, response.model_dump(), ttl=120)
    return response


@router.get("/{technique_id}")
async def get_technique_detail(
    technique_id: str,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get technique detail with linked intel items."""
    # Get technique
    result = await db.execute(
        select(AttackTechnique).where(AttackTechnique.id == technique_id)
    )
    technique = result.scalar_one_or_none()
    if not technique:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Technique not found")

    # Get linked intel items
    linked_stmt = (
        select(IntelItem)
        .join(
            IntelAttackLink,
            (IntelItem.id == IntelAttackLink.intel_id)
            & (IntelItem.ingested_at == IntelAttackLink.intel_ingested_at),
        )
        .where(IntelAttackLink.technique_id == technique_id)
        .order_by(IntelItem.risk_score.desc())
        .limit(50)
    )
    intel_result = await db.execute(linked_stmt)
    intel_items = list(intel_result.scalars().all())

    # Get subtechniques
    sub_stmt = (
        select(AttackTechnique)
        .where(AttackTechnique.parent_id == technique_id)
        .order_by(AttackTechnique.id)
    )
    sub_result = await db.execute(sub_stmt)
    subtechniques = list(sub_result.scalars().all())

    from app.schemas import IntelItemResponse
    return {
        "technique": AttackTechniqueResponse.model_validate(technique),
        "intel_items": [IntelItemResponse.model_validate(i) for i in intel_items],
        "subtechniques": [AttackTechniqueResponse.model_validate(s) for s in subtechniques],
        "intel_count": len(intel_items),
    }


@router.get("/intel/{item_id}/techniques", response_model=list[IntelAttackLinkResponse])
async def get_intel_techniques(
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get ATT&CK techniques mapped to a specific intel item."""
    stmt = (
        select(
            IntelAttackLink.technique_id,
            IntelAttackLink.confidence,
            IntelAttackLink.mapping_type,
            AttackTechnique.name.label("technique_name"),
            AttackTechnique.tactic,
            AttackTechnique.tactic_label,
            AttackTechnique.url,
        )
        .join(AttackTechnique, AttackTechnique.id == IntelAttackLink.technique_id)
        .where(IntelAttackLink.intel_id == item_id)
        .order_by(AttackTechnique.tactic, AttackTechnique.id)
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        IntelAttackLinkResponse(
            technique_id=r.technique_id,
            technique_name=r.technique_name,
            tactic=r.tactic,
            tactic_label=r.tactic_label,
            confidence=r.confidence,
            mapping_type=r.mapping_type,
            url=r.url,
        )
        for r in rows
    ]
