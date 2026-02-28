"""Notification & alerting API routes.

Provides:
- GET /notifications — list notifications (with filters)
- GET /notifications/unread-count — quick unread badge count
- GET /notifications/stats — dashboard-ready notification stats
- POST /notifications/mark-read — mark specific notifications as read
- POST /notifications/mark-all-read — mark all as read
- DELETE /notifications/{id} — delete single notification
- DELETE /notifications — clear all notifications
- GET /notifications/rules — list notification rules
- POST /notifications/rules — create a new rule
- PUT /notifications/rules/{id} — update a rule
- DELETE /notifications/rules/{id} — delete a rule
- POST /notifications/rules/{id}/toggle — toggle rule active state
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.middleware.auth import get_current_user, require_viewer
from app.models.models import User
from app.schemas import (
    NotificationListResponse,
    NotificationMarkRead,
    NotificationResponse,
    NotificationRuleCreate,
    NotificationRuleResponse,
    NotificationRuleUpdate,
    NotificationStatsResponse,
)
from app.services import notifications as notif_service

router = APIRouter(prefix="/notifications", tags=["notifications"])


# ─── Notification Endpoints ───────────────────────────────


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    unread_only: bool = Query(False),
    category: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Get notifications for the current user."""
    items, total = await notif_service.get_notifications(
        db,
        user.id,
        unread_only=unread_only,
        category=category,
        limit=limit,
        offset=offset,
    )
    unread = await notif_service.get_unread_count(db, user.id)
    return NotificationListResponse(
        notifications=[NotificationResponse.model_validate(n) for n in items],
        total=total,
        unread_count=unread,
    )


@router.get("/unread-count")
async def unread_count(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Quick endpoint for notification bell badge."""
    count = await notif_service.get_unread_count(db, user.id)
    return {"unread_count": count}


@router.get("/stats", response_model=NotificationStatsResponse)
async def notification_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get notification stats for dashboard enrichment."""
    stats = await notif_service.get_notification_stats(db, user.id)
    return stats


@router.post("/mark-read")
async def mark_read(
    body: NotificationMarkRead,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Mark specific notifications as read."""
    count = await notif_service.mark_read(db, user.id, body.notification_ids)
    return {"marked": count}


@router.post("/mark-all-read")
async def mark_all_read(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Mark all user notifications as read."""
    count = await notif_service.mark_all_read(db, user.id)
    return {"marked": count}


@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a single notification."""
    ok = await notif_service.delete_notification(db, user.id, notification_id)
    if not ok:
        raise HTTPException(404, "Notification not found")
    return {"deleted": True}


@router.delete("")
async def clear_all(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Clear all notifications for the current user."""
    count = await notif_service.clear_all_notifications(db, user.id)
    return {"cleared": count}


# ─── Rule Endpoints ──────────────────────────────────────


@router.get("/rules", response_model=list[NotificationRuleResponse])
async def list_rules(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get all notification rules for the current user."""
    rules = await notif_service.get_rules(db, user.id)
    return [NotificationRuleResponse.model_validate(r) for r in rules]


@router.post("/rules", response_model=NotificationRuleResponse, status_code=201)
async def create_rule(
    body: NotificationRuleCreate,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new notification rule."""
    rule = await notif_service.create_rule(db, user.id, body.model_dump())
    return NotificationRuleResponse.model_validate(rule)


@router.put("/rules/{rule_id}", response_model=NotificationRuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: NotificationRuleUpdate,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an existing notification rule."""
    data = body.model_dump(exclude_none=True)
    rule = await notif_service.update_rule(db, user.id, rule_id, data)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return NotificationRuleResponse.model_validate(rule)


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a notification rule (system rules cannot be deleted)."""
    result = await notif_service.delete_rule(db, user.id, rule_id)
    if result == "not_found":
        raise HTTPException(404, "Rule not found")
    if result == "system":
        raise HTTPException(403, "System rules cannot be deleted")
    return {"deleted": True}


@router.post("/rules/{rule_id}/toggle", response_model=NotificationRuleResponse)
async def toggle_rule(
    rule_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Toggle a notification rule's active state."""
    rule = await notif_service.toggle_rule(db, user.id, rule_id)
    if not rule:
        raise HTTPException(404, "Rule not found")
    return NotificationRuleResponse.model_validate(rule)


# ─── Webhook Test Endpoint ───────────────────────────────


@router.post("/webhook-test")
async def test_webhook(
    user: Annotated[User, Depends(require_viewer)],
    url: str = Query(..., description="Webhook URL to test"),
    secret: str | None = Query(None, description="Optional HMAC secret"),
):
    """Send a test notification to a webhook URL to verify connectivity."""
    from app.services.webhook import deliver_webhook_async

    test_notif = {
        "title": "IntelWatch Test Notification",
        "message": "This is a test notification from IntelWatch to verify your webhook configuration.",
        "severity": "info",
        "category": "test",
        "entity_type": None,
        "entity_id": None,
        "metadata": {"test": True},
    }
    result = await deliver_webhook_async(url, test_notif, secret=secret)
    return result
