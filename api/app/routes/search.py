"""Search endpoint."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.middleware.auth import require_viewer
from app.models.models import User
from app.schemas import SearchRequest, SearchResponse
from app.services.search import global_search, search_aggregations

router = APIRouter(prefix="/search", tags=["search"])


@router.post("", response_model=SearchResponse)
async def search(
    request: SearchRequest,
    user: Annotated[User, Depends(require_viewer)],
):
    """Global IOC search with auto-detection."""
    result = await global_search(
        query=request.query,
        feed_type=request.feed_type.value if request.feed_type else None,
        severity=request.severity.value if request.severity else None,
        asset_type=request.asset_type.value if request.asset_type else None,
        date_from=request.date_from.isoformat() if request.date_from else None,
        date_to=request.date_to.isoformat() if request.date_to else None,
        page=request.page,
        page_size=request.page_size,
        sort_by=request.sort_by,
        sort_dir=request.sort_dir,
    )
    return result


@router.get("/stats")
async def search_stats(
    user: Annotated[User, Depends(require_viewer)],
):
    """Aggregation stats for search UI (type distribution, severity, sources)."""
    return await search_aggregations()
