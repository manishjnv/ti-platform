"""Case / Incident Management API routes.

Provides:
- GET    /cases              — list cases (paginated, filtered)
- POST   /cases              — create a new case
- GET    /cases/stats        — aggregate case statistics
- GET    /cases/{id}         — get case with items & timeline
- PUT    /cases/{id}         — update a case
- DELETE /cases/{id}         — delete a case
- POST   /cases/{id}/items   — link intel/IOC/technique to case
- DELETE /cases/{id}/items/{item_id} — remove linked item
- POST   /cases/{id}/comments — add a comment to case timeline
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.middleware.auth import require_analyst, require_viewer
from app.models.models import User
from app.schemas import (
    CaseCreate,
    CaseCommentCreate,
    CaseItemCreate,
    CaseItemResponse,
    CaseActivityResponse,
    CaseListResponse,
    CaseResponse,
    CaseStatsResponse,
    CaseUpdate,
)
from app.services import cases as case_service

router = APIRouter(prefix="/cases", tags=["cases"])


# ─── Helpers ──────────────────────────────────────────────

async def _enrich_case(db: AsyncSession, c, include_items: bool = False) -> CaseResponse:
    """Convert a Case ORM object to CaseResponse with user emails."""
    resp = CaseResponse.model_validate(c)

    # Owner email
    owner = (await db.execute(
        select(User).where(User.id == c.owner_id)
    )).scalar_one_or_none()
    if owner:
        resp.owner_email = owner.email

    # Assignee email
    if c.assignee_id:
        assignee = (await db.execute(
            select(User).where(User.id == c.assignee_id)
        )).scalar_one_or_none()
        if assignee:
            resp.assignee_email = assignee.email

    if include_items:
        items = await case_service.get_case_items(db, c.id)
        resp.items = [CaseItemResponse.model_validate(i) for i in items]

        activities = await case_service.get_case_activities(db, c.id)

        # Batch-load user emails for activities
        activity_user_ids = {a.user_id for a in activities if a.user_id}
        activity_user_map: dict[uuid.UUID, str] = {}
        if activity_user_ids:
            rows = (await db.execute(
                select(User.id, User.email).where(User.id.in_(list(activity_user_ids)))
            )).all()
            activity_user_map = {r[0]: r[1] for r in rows}

        enriched_activities = []
        for a in activities:
            ar = CaseActivityResponse(
                id=a.id,
                case_id=a.case_id,
                user_id=a.user_id,
                action=a.action,
                detail=a.detail,
                metadata=a.meta,
                created_at=a.created_at,
            )
            if a.user_id:
                ar.user_email = activity_user_map.get(a.user_id)
            enriched_activities.append(ar)
        resp.activities = enriched_activities

    return resp


# ─── List & Create ────────────────────────────────────────


@router.get("", response_model=CaseListResponse)
async def list_cases(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    priority: str | None = Query(None),
    case_type: str | None = Query(None),
    assignee_id: uuid.UUID | None = Query(None),
    search: str | None = Query(None),
    sort_by: str = Query("updated_at"),
    sort_order: str = Query("desc"),
):
    """List cases with pagination and filters."""
    cases, total = await case_service.list_cases(
        db,
        page=page,
        page_size=page_size,
        status=status,
        priority=priority,
        case_type=case_type,
        assignee_id=assignee_id,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    pages = max(1, -(-total // page_size))

    # Batch-load user emails for owner/assignee enrichment
    user_ids = set()
    for c in cases:
        user_ids.add(c.owner_id)
        if c.assignee_id:
            user_ids.add(c.assignee_id)
    user_map: dict[uuid.UUID, str] = {}
    if user_ids:
        rows = (await db.execute(
            select(User.id, User.email).where(User.id.in_(list(user_ids)))
        )).all()
        user_map = {r[0]: r[1] for r in rows}

    enriched = []
    for c in cases:
        resp = CaseResponse.model_validate(c)
        resp.items = []
        resp.activities = []
        resp.owner_email = user_map.get(c.owner_id)
        if c.assignee_id:
            resp.assignee_email = user_map.get(c.assignee_id)
        enriched.append(resp)

    return CaseListResponse(
        cases=enriched,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("", response_model=CaseResponse, status_code=201)
async def create_case(
    body: CaseCreate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new case. Requires analyst role."""
    data = body.model_dump()
    # Convert enum values
    for key in ("case_type", "priority", "severity", "tlp"):
        if key in data and hasattr(data[key], "value"):
            data[key] = data[key].value

    c = await case_service.create_case(db, user.id, data)
    await db.commit()
    return await _enrich_case(db, c)


# ─── Stats ────────────────────────────────────────────────


@router.get("/stats", response_model=CaseStatsResponse)
async def get_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get aggregate case statistics."""
    stats = await case_service.get_case_stats(db)
    return CaseStatsResponse(**stats)


# ─── Single Case ─────────────────────────────────────────


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a case with linked items and activity timeline."""
    c = await case_service.get_case(db, case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return await _enrich_case(db, c, include_items=True)


@router.put("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: uuid.UUID,
    body: CaseUpdate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update case fields. Requires analyst role."""
    data = body.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(400, "No fields to update")

    # Convert enum values
    for key in ("case_type", "status", "priority", "severity", "tlp"):
        if key in data and hasattr(data[key], "value"):
            data[key] = data[key].value

    c = await case_service.update_case(db, case_id, user.id, data)
    if not c:
        raise HTTPException(404, "Case not found")
    await db.commit()
    return await _enrich_case(db, c, include_items=True)


@router.delete("/{case_id}")
async def delete_case(
    case_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a case. Requires analyst role."""
    ok = await case_service.delete_case(db, case_id)
    if not ok:
        raise HTTPException(404, "Case not found")
    await db.commit()
    return {"deleted": True}


# ─── Linked Items ─────────────────────────────────────────


@router.post("/{case_id}/items", response_model=CaseItemResponse, status_code=201)
async def add_item(
    case_id: uuid.UUID,
    body: CaseItemCreate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Link an intel item, IOC, or technique to a case."""
    result = await case_service.add_case_item(db, case_id, user.id, body.model_dump())
    if result == "duplicate":
        raise HTTPException(409, "Item already linked to this case")
    if not result:
        raise HTTPException(400, "Case not found")
    await db.commit()
    return CaseItemResponse.model_validate(result)


@router.delete("/{case_id}/items/{item_id}")
async def remove_item(
    case_id: uuid.UUID,
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove a linked item from a case."""
    ok = await case_service.remove_case_item(db, case_id, item_id, user_id=user.id)
    if not ok:
        raise HTTPException(404, "Item not found")
    await db.commit()
    return {"deleted": True}


# ─── Comments ─────────────────────────────────────────────


@router.post("/{case_id}/comments", response_model=CaseActivityResponse)
async def add_comment(
    case_id: uuid.UUID,
    body: CaseCommentCreate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a comment to the case timeline."""
    c = await case_service.get_case(db, case_id)
    if not c:
        raise HTTPException(404, "Case not found")

    activity = await case_service.add_comment(db, case_id, user.id, body.comment)
    await db.commit()

    return CaseActivityResponse(
        id=activity.id,
        case_id=activity.case_id,
        user_id=activity.user_id,
        user_email=user.email,
        action=activity.action,
        detail=activity.detail,
        metadata=activity.meta,
        created_at=activity.created_at,
    )
