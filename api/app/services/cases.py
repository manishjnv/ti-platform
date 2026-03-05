"""Case / Incident Management service — CRUD, timeline, linked items."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, func, select, case as sa_case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.models import Case, CaseItem, CaseActivity, User

logger = get_logger(__name__)

# ─── Status Transition Rules ─────────────────────────────

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "new": {"in_progress", "pending", "closed"},
    "in_progress": {"pending", "resolved", "closed"},
    "pending": {"in_progress", "resolved", "closed"},
    "resolved": {"closed", "in_progress"},
    "closed": {"in_progress"},
}


def validate_status_transition(current: str, target: str) -> bool:
    """Check whether a status transition is allowed."""
    if current == target:
        return True
    return target in ALLOWED_TRANSITIONS.get(current, set())


# ─── CRUD ─────────────────────────────────────────────────


async def create_case(
    db: AsyncSession,
    owner_id: uuid.UUID,
    data: dict,
) -> Case:
    c = Case(
        title=data["title"],
        description=data.get("description"),
        case_type=data.get("case_type", "investigation"),
        status="new",
        priority=data.get("priority", "medium"),
        severity=data.get("severity", "medium"),
        tlp=data.get("tlp", "TLP:GREEN"),
        owner_id=owner_id,
        assignee_id=data.get("assignee_id"),
        tags=data.get("tags", []),
    )
    db.add(c)
    await db.flush()
    await db.refresh(c)

    # Record creation activity
    await _add_activity(db, c.id, owner_id, "created", f"Case created: {c.title}")

    logger.info("case_created", case_id=str(c.id), title=c.title)
    return c


async def get_case(db: AsyncSession, case_id: uuid.UUID) -> Case | None:
    result = await db.execute(select(Case).where(Case.id == case_id))
    return result.scalar_one_or_none()


async def list_cases(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    priority: str | None = None,
    case_type: str | None = None,
    assignee_id: uuid.UUID | None = None,
    search: str | None = None,
    sort_by: str = "updated_at",
    sort_order: str = "desc",
    severity: str | None = None,
    tlp: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    tag: str | None = None,
) -> tuple[list[Case], int]:
    query = select(Case)

    if status:
        query = query.where(Case.status == status)
    if priority:
        query = query.where(Case.priority == priority)
    if case_type:
        query = query.where(Case.case_type == case_type)
    if assignee_id:
        query = query.where(Case.assignee_id == assignee_id)
    if severity:
        query = query.where(Case.severity == severity)
    if tlp:
        query = query.where(Case.tlp == tlp)
    if date_from:
        query = query.where(Case.created_at >= date_from)
    if date_to:
        query = query.where(Case.created_at <= date_to)
    if tag:
        query = query.where(Case.tags.contains([tag]))
    if search:
        query = query.where(Case.title.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    col = getattr(Case, sort_by, Case.updated_at)
    query = query.order_by(col.desc() if sort_order == "desc" else col.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    return list(result.scalars().all()), total


async def update_case(
    db: AsyncSession,
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    data: dict,
) -> Case | str | None:
    c = await get_case(db, case_id)
    if not c:
        return None

    # Validate status transition
    if "status" in data and data["status"] != c.status:
        if not validate_status_transition(c.status, data["status"]):
            return "invalid_transition"

    changes = []
    for key, value in data.items():
        old = getattr(c, key, None)
        if old != value:
            setattr(c, key, value)
            changes.append(f"{key}: {old} → {value}")

    # Auto-set closed_at
    if data.get("status") in ("resolved", "closed") and not c.closed_at:
        c.closed_at = datetime.now(timezone.utc)
    elif data.get("status") not in (None, "resolved", "closed"):
        c.closed_at = None

    c.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(c)

    if changes:
        await _add_activity(db, case_id, user_id, "updated", "; ".join(changes))

    return c


async def delete_case(db: AsyncSession, case_id: uuid.UUID) -> bool:
    c = await get_case(db, case_id)
    if not c:
        return False
    await db.execute(delete(CaseActivity).where(CaseActivity.case_id == case_id))
    await db.execute(delete(CaseItem).where(CaseItem.case_id == case_id))
    await db.execute(delete(Case).where(Case.id == case_id))
    return True


# ─── Case Items ───────────────────────────────────────────


async def get_case_items(db: AsyncSession, case_id: uuid.UUID) -> list[CaseItem]:
    result = await db.execute(
        select(CaseItem).where(CaseItem.case_id == case_id).order_by(CaseItem.created_at.desc())
    )
    return list(result.scalars().all())


async def add_case_item(
    db: AsyncSession,
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    data: dict,
) -> CaseItem | str | None:
    c = await get_case(db, case_id)
    if not c:
        return None

    item = CaseItem(
        case_id=case_id,
        item_type=data["item_type"],
        item_id=data["item_id"],
        item_title=data.get("item_title"),
        item_metadata=data.get("item_metadata", {}),
        added_by=user_id,
        notes=data.get("notes"),
    )
    db.add(item)

    # Update counter
    if data["item_type"] == "intel":
        c.linked_intel_count += 1
    elif data["item_type"] == "ioc":
        c.linked_ioc_count += 1
    else:
        c.linked_observable_count += 1
    c.updated_at = datetime.now(timezone.utc)

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return "duplicate"
    await db.refresh(item)

    await _add_activity(
        db, case_id, user_id, "item_added",
        f"Linked {data['item_type']}: {data.get('item_title') or data['item_id']}",
    )

    return item


async def remove_case_item(
    db: AsyncSession,
    case_id: uuid.UUID,
    item_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> bool:
    result = await db.execute(
        select(CaseItem).where(CaseItem.id == item_id, CaseItem.case_id == case_id)
    )
    item = result.scalar_one_or_none()
    if not item:
        return False

    item_label = f"{item.item_type}: {item.item_title or item.item_id}"

    # Update counter
    c = await get_case(db, case_id)
    if c:
        if item.item_type == "intel":
            c.linked_intel_count = max(0, c.linked_intel_count - 1)
        elif item.item_type == "ioc":
            c.linked_ioc_count = max(0, c.linked_ioc_count - 1)
        else:
            c.linked_observable_count = max(0, c.linked_observable_count - 1)
        c.updated_at = datetime.now(timezone.utc)

    await db.execute(delete(CaseItem).where(CaseItem.id == item_id))

    if user_id:
        await _add_activity(db, case_id, user_id, "item_removed", f"Removed {item_label}")

    return True


# ─── Activity / Timeline ─────────────────────────────────


async def get_case_activities(db: AsyncSession, case_id: uuid.UUID) -> list[CaseActivity]:
    result = await db.execute(
        select(CaseActivity).where(CaseActivity.case_id == case_id).order_by(CaseActivity.created_at.desc())
    )
    return list(result.scalars().all())


async def add_comment(
    db: AsyncSession,
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    comment: str,
) -> CaseActivity:
    return await _add_activity(db, case_id, user_id, "comment", comment)


async def _add_activity(
    db: AsyncSession,
    case_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    detail: str | None = None,
    metadata: dict | None = None,
) -> CaseActivity:
    activity = CaseActivity(
        case_id=case_id,
        user_id=user_id,
        action=action,
        detail=detail,
    )
    if metadata:
        activity.meta = metadata
    db.add(activity)
    await db.flush()
    await db.refresh(activity)
    return activity


# ─── Stats ────────────────────────────────────────────────


async def get_case_stats(db: AsyncSession) -> dict:
    total = (await db.execute(select(func.count()).select_from(Case))).scalar() or 0

    open_cases = (await db.execute(
        select(func.count()).select_from(Case).where(Case.status.in_(["new", "in_progress", "pending"]))
    )).scalar() or 0

    # By status
    status_rows = (await db.execute(
        select(Case.status, func.count()).group_by(Case.status)
    )).all()
    by_status = {r[0]: r[1] for r in status_rows}

    # By priority
    priority_rows = (await db.execute(
        select(Case.priority, func.count()).group_by(Case.priority)
    )).all()
    by_priority = {r[0]: r[1] for r in priority_rows}

    # By type
    type_rows = (await db.execute(
        select(Case.case_type, func.count()).group_by(Case.case_type)
    )).all()
    by_type = {r[0]: r[1] for r in type_rows}

    # Recently closed (last 7 days)
    from datetime import timedelta
    recent_closed = (await db.execute(
        select(func.count()).select_from(Case).where(
            Case.status.in_(["resolved", "closed"]),
            Case.closed_at >= datetime.now(timezone.utc) - timedelta(days=7),
        )
    )).scalar() or 0

    return {
        "total_cases": total,
        "open_cases": open_cases,
        "by_status": by_status,
        "by_priority": by_priority,
        "by_type": by_type,
        "recent_closed": recent_closed,
    }


# ─── Bulk Operations ──────────────────────────────────────


async def bulk_update_status(
    db: AsyncSession,
    case_ids: list[uuid.UUID],
    status: str,
    user_id: uuid.UUID,
) -> int:
    """Update status for multiple cases. Returns count of updated."""
    updated = 0
    for cid in case_ids:
        c = await get_case(db, cid)
        if not c:
            continue
        if not validate_status_transition(c.status, status):
            continue
        old = c.status
        c.status = status
        if status in ("resolved", "closed") and not c.closed_at:
            c.closed_at = datetime.now(timezone.utc)
        elif status not in ("resolved", "closed"):
            c.closed_at = None
        c.updated_at = datetime.now(timezone.utc)
        await _add_activity(db, cid, user_id, "status_changed", f"status: {old} → {status}")
        updated += 1
    return updated


async def bulk_delete(
    db: AsyncSession,
    case_ids: list[uuid.UUID],
) -> int:
    """Delete multiple cases. Returns count of deleted."""
    deleted = 0
    for cid in case_ids:
        if await delete_case(db, cid):
            deleted += 1
    return deleted


async def bulk_assign(
    db: AsyncSession,
    case_ids: list[uuid.UUID],
    assignee_id: uuid.UUID | None,
    user_id: uuid.UUID,
) -> int:
    """Assign multiple cases. Returns count of updated."""
    updated = 0
    for cid in case_ids:
        c = await get_case(db, cid)
        if not c:
            continue
        old_id = c.assignee_id
        c.assignee_id = assignee_id
        c.updated_at = datetime.now(timezone.utc)
        await _add_activity(db, cid, user_id, "assigned", f"assignee: {old_id} → {assignee_id}")
        updated += 1
    return updated


# ─── Export ───────────────────────────────────────────────


async def export_cases_json(db: AsyncSession, case_ids: list[uuid.UUID] | None = None) -> str:
    """Export cases as JSON string."""
    if case_ids:
        result = await db.execute(select(Case).where(Case.id.in_(case_ids)))
    else:
        result = await db.execute(select(Case).order_by(Case.updated_at.desc()))
    cases = list(result.scalars().all())

    export_data = []
    for c in cases:
        items_result = await db.execute(
            select(CaseItem).where(CaseItem.case_id == c.id)
        )
        items = list(items_result.scalars().all())

        export_data.append({
            "id": str(c.id),
            "title": c.title,
            "description": c.description,
            "case_type": c.case_type,
            "status": c.status,
            "priority": c.priority,
            "severity": c.severity,
            "tlp": c.tlp,
            "tags": c.tags,
            "linked_intel_count": c.linked_intel_count,
            "linked_ioc_count": c.linked_ioc_count,
            "linked_observable_count": c.linked_observable_count,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
            "closed_at": c.closed_at.isoformat() if c.closed_at else None,
            "items": [
                {
                    "item_type": i.item_type,
                    "item_id": i.item_id,
                    "item_title": i.item_title,
                    "notes": i.notes,
                }
                for i in items
            ],
        })

    return json.dumps(export_data, indent=2)


async def export_cases_csv(db: AsyncSession, case_ids: list[uuid.UUID] | None = None) -> str:
    """Export cases as CSV string."""
    if case_ids:
        result = await db.execute(select(Case).where(Case.id.in_(case_ids)))
    else:
        result = await db.execute(select(Case).order_by(Case.updated_at.desc()))
    cases = list(result.scalars().all())

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Title", "Description", "Type", "Status", "Priority",
        "Severity", "TLP", "Tags", "Intel", "IOCs", "Observables",
        "Created", "Updated", "Closed",
    ])
    for c in cases:
        writer.writerow([
            str(c.id), c.title, c.description or "", c.case_type,
            c.status, c.priority, c.severity, c.tlp,
            "; ".join(c.tags), c.linked_intel_count, c.linked_ioc_count,
            c.linked_observable_count,
            c.created_at.isoformat(), c.updated_at.isoformat(),
            c.closed_at.isoformat() if c.closed_at else "",
        ])
    return output.getvalue()


async def get_assignable_users(db: AsyncSession) -> list[dict]:
    """Get users that can be assigned to cases (admin + analyst)."""
    result = await db.execute(
        select(User.id, User.email, User.name)
        .where(User.is_active == True, User.role.in_(["admin", "analyst"]))
        .order_by(User.email)
    )
    return [{"id": str(r[0]), "email": r[1], "name": r[2]} for r in result.all()]
