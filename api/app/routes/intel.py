"""Intel items endpoints — feed listing, detail, export."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import cache_key, get_cached, set_cached
from app.core.config import get_settings
from app.middleware.auth import get_current_user, require_viewer
from app.models.models import User
from app.schemas import IntelItemListResponse, IntelItemResponse
from app.services import database as db_service
from app.services.export import export_to_excel

router = APIRouter(prefix="/intel", tags=["intel"])
settings = get_settings()


@router.get("", response_model=IntelItemListResponse)
async def list_intel_items(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: str | None = None,
    feed_type: str | None = None,
    source_name: str | None = None,
    sort_by: str = Query("ingested_at", pattern="^(ingested_at|risk_score|severity|published_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    """List intel items with pagination and filters."""
    ck = cache_key("intel_list", page, page_size, severity, feed_type, source_name, sort_by, sort_order)
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
