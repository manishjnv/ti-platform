"""Admin & user management endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from redis import Redis
from rq import Queue
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import get_settings
from app.middleware.auth import get_current_user, require_admin, require_viewer
from app.middleware.audit import log_audit
from app.models.models import User
from app.schemas import UserResponse, UserUpdate, FeedStatusResponse, AuditLogResponse
from app.services import database as db_service

router = APIRouter(tags=["admin"])
settings = get_settings()


@router.get("/me", response_model=UserResponse)
async def get_me(user: Annotated[User, Depends(get_current_user)]):
    """Get current user info."""
    return UserResponse.model_validate(user)


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """List all users (admin only)."""
    users = await db_service.get_users(db)
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    update: UserUpdate,
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update user role/status (admin only)."""
    target = await db_service.update_user_role(db, user_id, update.role.value if update.role else None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    await log_audit(
        db,
        user_id=str(user.id),
        action="update_user",
        resource_type="user",
        resource_id=str(user_id),
        details=update.model_dump(exclude_none=True),
    )
    return UserResponse.model_validate(target)


@router.get("/feeds/status", response_model=list[FeedStatusResponse])
async def get_feed_status(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get status of all feed connectors."""
    from sqlalchemy import select
    from app.models.models import FeedSyncState

    result = await db.execute(select(FeedSyncState))
    feeds = result.scalars().all()
    return [FeedStatusResponse.model_validate(f) for f in feeds]


@router.post("/feeds/{feed_name}/trigger")
async def trigger_feed(
    feed_name: str,
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Manually trigger a feed ingestion (admin only)."""
    valid_feeds = ["nvd", "cisa_kev", "urlhaus", "abuseipdb", "otx"]
    if feed_name not in valid_feeds:
        raise HTTPException(status_code=400, detail=f"Invalid feed. Options: {valid_feeds}")

    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("high", connection=redis_conn)
    job = q.enqueue("worker.tasks.ingest_feed", feed_name, job_timeout=300)

    await log_audit(
        db,
        user_id=str(user.id),
        action="trigger_feed",
        resource_type="feed",
        resource_id=feed_name,
    )
    return {"status": "queued", "job_id": job.id, "feed": feed_name}


@router.post("/feeds/trigger-all")
async def trigger_all_feeds(
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Trigger all feed ingestions (admin only)."""
    redis_conn = Redis.from_url(settings.redis_url)
    q = Queue("default", connection=redis_conn)
    job = q.enqueue("worker.tasks.ingest_all_feeds", job_timeout=600)

    await log_audit(
        db, user_id=str(user.id), action="trigger_all_feeds", resource_type="feed"
    )
    return {"status": "queued", "job_id": job.id}
