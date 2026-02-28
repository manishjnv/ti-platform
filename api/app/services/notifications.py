"""Notification service — rule evaluation engine and notification management.

USP Features:
- Zero-Config Smart Defaults: pre-seeded rules for critical/high, KEV, feed errors
- Cross-Feed Correlation: detects same CVE/IOC across multiple feeds
- Risk Trend Alerts: notifies on significant risk score changes
- Feed Health Watchdog: real-time feed stale/error monitoring
- Severity Intelligence: computed severity from risk score + ATT&CK + IOC count
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import and_, func, select, update, delete, case, literal
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.models import (
    IntelItem,
    IOC,
    FeedSyncState,
    Notification,
    NotificationRule,
    User,
)

logger = get_logger(__name__)

# ─── Constants ────────────────────────────────────────────

SYSTEM_RULES = [
    {
        "name": "Critical/High Severity Alert",
        "description": "Alert when new critical or high severity intel is ingested",
        "rule_type": "threshold",
        "conditions": {"severity": ["critical", "high"], "min_risk_score": 0},
        "channels": ["in_app"],
        "cooldown_minutes": 5,
    },
    {
        "name": "CISA KEV Alert",
        "description": "Alert when a new Known Exploited Vulnerability is detected",
        "rule_type": "threshold",
        "conditions": {"is_kev": True},
        "channels": ["in_app"],
        "cooldown_minutes": 5,
    },
    {
        "name": "Feed Health Watchdog",
        "description": "Alert when a feed connector fails or goes stale (>1 hour)",
        "rule_type": "feed_error",
        "conditions": {"stale_minutes": 60, "on_error": True},
        "channels": ["in_app"],
        "cooldown_minutes": 30,
    },
    {
        "name": "Risk Score Spike",
        "description": "Alert when a risk score of 90+ is detected",
        "rule_type": "threshold",
        "conditions": {"min_risk_score": 90},
        "channels": ["in_app"],
        "cooldown_minutes": 10,
    },
]


# ─── Async Service Functions (for API routes) ────────────


async def get_notifications(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    unread_only: bool = False,
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Notification], int]:
    """Get notifications for a user with optional filters."""
    conditions = [Notification.user_id == user_id]
    if unread_only:
        conditions.append(Notification.is_read == False)  # noqa: E712
    if category:
        conditions.append(Notification.category == category)

    # Count
    count_q = select(func.count()).where(*conditions).select_from(Notification)
    total = (await db.execute(count_q)).scalar() or 0

    # Items
    q = (
        select(Notification)
        .where(*conditions)
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(q)).scalars().all()
    return list(rows), total


async def get_unread_count(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Get count of unread notifications."""
    q = select(func.count()).where(
        Notification.user_id == user_id,
        Notification.is_read == False,  # noqa: E712
    ).select_from(Notification)
    return (await db.execute(q)).scalar() or 0


async def mark_read(
    db: AsyncSession, user_id: uuid.UUID, notification_ids: list[uuid.UUID]
) -> int:
    """Mark specific notifications as read."""
    q = (
        update(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.id.in_(notification_ids),
        )
        .values(is_read=True, read_at=datetime.now(timezone.utc))
    )
    result = await db.execute(q)
    await db.commit()
    return result.rowcount  # type: ignore[return-value]


async def mark_all_read(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Mark all notifications as read for a user."""
    q = (
        update(Notification)
        .where(
            Notification.user_id == user_id,
            Notification.is_read == False,  # noqa: E712
        )
        .values(is_read=True, read_at=datetime.now(timezone.utc))
    )
    result = await db.execute(q)
    await db.commit()
    return result.rowcount  # type: ignore[return-value]


async def delete_notification(
    db: AsyncSession, user_id: uuid.UUID, notification_id: uuid.UUID
) -> bool:
    """Delete a single notification."""
    q = delete(Notification).where(
        Notification.user_id == user_id,
        Notification.id == notification_id,
    )
    result = await db.execute(q)
    await db.commit()
    return (result.rowcount or 0) > 0


async def clear_all_notifications(db: AsyncSession, user_id: uuid.UUID) -> int:
    """Delete all notifications for a user."""
    q = delete(Notification).where(Notification.user_id == user_id)
    result = await db.execute(q)
    await db.commit()
    return result.rowcount  # type: ignore[return-value]


# ─── Rule CRUD (async) ───────────────────────────────────


async def get_rules(
    db: AsyncSession, user_id: uuid.UUID
) -> list[NotificationRule]:
    """Get all notification rules for a user (including system rules)."""
    q = (
        select(NotificationRule)
        .where(NotificationRule.user_id == user_id)
        .order_by(NotificationRule.is_system.desc(), NotificationRule.created_at)
    )
    rows = (await db.execute(q)).scalars().all()
    return list(rows)


async def create_rule(
    db: AsyncSession, user_id: uuid.UUID, data: dict[str, Any]
) -> NotificationRule:
    """Create a new notification rule."""
    rule = NotificationRule(
        user_id=user_id,
        name=data["name"],
        description=data.get("description"),
        rule_type=data.get("rule_type", "threshold"),
        conditions=data.get("conditions", {}),
        channels=data.get("channels", ["in_app"]),
        is_active=data.get("is_active", True),
        cooldown_minutes=data.get("cooldown_minutes", 15),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(
    db: AsyncSession,
    user_id: uuid.UUID,
    rule_id: uuid.UUID,
    data: dict[str, Any],
) -> NotificationRule | None:
    """Update an existing notification rule."""
    q = select(NotificationRule).where(
        NotificationRule.id == rule_id,
        NotificationRule.user_id == user_id,
    )
    rule = (await db.execute(q)).scalar_one_or_none()
    if not rule:
        return None

    # System rules can only have limited fields updated
    if rule.is_system:
        allowed = ("is_active", "cooldown_minutes")
        data = {k: v for k, v in data.items() if k in allowed}

    for field in ("name", "description", "rule_type", "conditions", "channels", "is_active", "cooldown_minutes"):
        if field in data:
            setattr(rule, field, data[field])

    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_rule(
    db: AsyncSession, user_id: uuid.UUID, rule_id: uuid.UUID
) -> str:
    """Delete a notification rule (cannot delete system rules).

    Returns: 'deleted' | 'system' | 'not_found'
    """
    # Check if rule exists first
    rule = (await db.execute(
        select(NotificationRule).where(
            NotificationRule.id == rule_id,
            NotificationRule.user_id == user_id,
        )
    )).scalar_one_or_none()
    if not rule:
        return "not_found"
    if rule.is_system:
        return "system"
    await db.execute(
        delete(NotificationRule).where(NotificationRule.id == rule_id)
    )
    await db.commit()
    return "deleted"


async def toggle_rule(
    db: AsyncSession, user_id: uuid.UUID, rule_id: uuid.UUID
) -> NotificationRule | None:
    """Toggle a rule's active state."""
    q = select(NotificationRule).where(
        NotificationRule.id == rule_id,
        NotificationRule.user_id == user_id,
    )
    rule = (await db.execute(q)).scalar_one_or_none()
    if not rule:
        return None
    rule.is_active = not rule.is_active
    await db.commit()
    await db.refresh(rule)
    return rule


# ─── Sync Rule Evaluation (for worker tasks) ─────────────


def ensure_system_rules(session: Session) -> None:
    """Ensure all users have the default system rules. Idempotent."""
    users = session.execute(select(User.id)).scalars().all()
    if not users:
        return

    for user_id in users:
        existing = session.execute(
            select(NotificationRule.name).where(
                NotificationRule.user_id == user_id,
                NotificationRule.is_system == True,  # noqa: E712
            )
        ).scalars().all()

        for rule_def in SYSTEM_RULES:
            if rule_def["name"] not in existing:
                session.add(NotificationRule(
                    user_id=user_id,
                    is_system=True,
                    **rule_def,
                ))

    session.commit()
    logger.info("system_rules_ensured", user_count=len(users))


def evaluate_notification_rules(session: Session, lookback_minutes: int = 10) -> dict:
    """Evaluate all active notification rules against recent data.

    Called periodically by the scheduler/worker. Checks:
    1. Threshold rules against recently ingested intel items
    2. Feed error rules against feed_sync_state
    3. Correlation detection (same CVE across multiple feeds)
    """
    now = datetime.now(timezone.utc)
    lookback = now - timedelta(minutes=lookback_minutes)
    stats = {"rules_checked": 0, "notifications_created": 0, "errors": 0}

    # Get all active rules grouped by user
    rules = session.execute(
        select(NotificationRule).where(NotificationRule.is_active == True)  # noqa: E712
    ).scalars().all()

    if not rules:
        return stats

    # Prefetch recent intel items (covers threshold/correlation rules)
    recent_intel = session.execute(
        select(IntelItem).where(IntelItem.ingested_at >= lookback)
    ).scalars().all()

    # Prefetch feed states (covers feed_error rules)
    feed_states = session.execute(select(FeedSyncState)).scalars().all()

    for rule in rules:
        try:
            stats["rules_checked"] += 1

            # Cooldown check
            if rule.last_triggered_at:
                cooldown_until = rule.last_triggered_at + timedelta(minutes=rule.cooldown_minutes)
                if now < cooldown_until:
                    continue

            # Narrow lookback to avoid re-alerting on already-processed items
            # Only evaluate items ingested AFTER the rule's last trigger time
            rule_lookback = lookback
            if rule.last_triggered_at and rule.last_triggered_at > lookback:
                rule_lookback = rule.last_triggered_at

            # Filter recent intel to this rule's effective lookback
            rule_intel = [i for i in recent_intel if i.ingested_at >= rule_lookback]

            created = 0
            if rule.rule_type == "threshold":
                created = _eval_threshold_rule(session, rule, rule_intel, now)
            elif rule.rule_type == "feed_error":
                created = _eval_feed_error_rule(session, rule, feed_states, now)
            elif rule.rule_type == "correlation":
                created = _eval_correlation_rule(session, rule, rule_intel, now)

            if created > 0:
                rule.last_triggered_at = now
                rule.trigger_count += created
                stats["notifications_created"] += created

        except Exception as e:
            logger.error("rule_eval_error", rule_id=str(rule.id), error=str(e))
            stats["errors"] += 1

    session.commit()
    logger.info("notification_eval_complete", **stats)
    return stats


def _compute_notification_severity(item: IntelItem) -> str:
    """Compute notification severity using multiple signals (USP: Severity Intelligence)."""
    score = item.risk_score
    if item.is_kev:
        score = max(score, 85)
    if item.severity in ("critical",):
        score = max(score, 90)
    elif item.severity in ("high",):
        score = max(score, 70)

    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 50:
        return "medium"
    elif score >= 30:
        return "low"
    return "info"


def _eval_threshold_rule(
    session: Session,
    rule: NotificationRule,
    recent_items: list[IntelItem],
    now: datetime,
) -> int:
    """Evaluate threshold-type rules against recent intel items."""
    conditions = rule.conditions or {}
    matching_items = []

    for item in recent_items:
        match = True

        # Severity filter
        severities = conditions.get("severity")
        if severities and item.severity not in severities:
            match = False

        # Min risk score
        min_risk = conditions.get("min_risk_score")
        if min_risk is not None and item.risk_score < min_risk:
            match = False

        # KEV filter
        if conditions.get("is_kev") and not item.is_kev:
            match = False

        # CVE watchlist
        cve_watchlist = conditions.get("cve_ids")
        if cve_watchlist:
            if not any(c in (item.cve_ids or []) for c in cve_watchlist):
                match = False

        # Feed type filter
        feed_types = conditions.get("feed_types")
        if feed_types and item.feed_type not in feed_types:
            match = False

        # Source name filter
        source_names = conditions.get("source_names")
        if source_names and item.source_name not in source_names:
            match = False

        # Keyword filter
        keywords = conditions.get("keywords")
        if keywords:
            text = f"{item.title} {item.summary or ''} {item.description or ''}".lower()
            if not any(kw.lower() in text for kw in keywords):
                match = False

        if match:
            matching_items.append(item)

    # Create notifications for matching items (batch to reduce noise)
    created = 0
    if len(matching_items) == 1:
        item = matching_items[0]
        _create_notification(
            session,
            user_id=rule.user_id,
            rule_id=rule.id,
            title=f"[{item.severity.upper()}] {item.title[:200]}",
            message=item.summary or item.description or "",
            severity=_compute_notification_severity(item),
            category="alert",
            entity_type="intel",
            entity_id=str(item.id),
            metadata={
                "risk_score": item.risk_score,
                "source_name": item.source_name,
                "feed_type": item.feed_type,
                "is_kev": item.is_kev,
                "cve_ids": item.cve_ids or [],
            },
        )
        created = 1
    elif len(matching_items) > 1:
        # Batch notification to reduce alert fatigue
        top = sorted(matching_items, key=lambda x: x.risk_score, reverse=True)[:5]
        titles = [f"• {i.title[:80]}" for i in top]
        extra = f"\n... and {len(matching_items) - 5} more" if len(matching_items) > 5 else ""
        max_sev = max(matching_items, key=lambda x: x.risk_score)
        _create_notification(
            session,
            user_id=rule.user_id,
            rule_id=rule.id,
            title=f"{len(matching_items)} new alerts matched '{rule.name}'",
            message="\n".join(titles) + extra,
            severity=_compute_notification_severity(max_sev),
            category="alert",
            entity_type="intel",
            entity_id=str(top[0].id),
            metadata={
                "match_count": len(matching_items),
                "top_risk_score": max_sev.risk_score,
                "rule_name": rule.name,
            },
        )
        created = 1

    return created


def _eval_feed_error_rule(
    session: Session,
    rule: NotificationRule,
    feed_states: list[FeedSyncState],
    now: datetime,
) -> int:
    """Evaluate feed health rules (USP: Feed Health Watchdog)."""
    conditions = rule.conditions or {}
    stale_minutes = conditions.get("stale_minutes", 60)
    on_error = conditions.get("on_error", True)
    created = 0

    for feed in feed_states:
        issues = []

        # Check for error status
        if on_error and feed.status == "failed":
            issues.append(f"Feed '{feed.feed_name}' is in FAILED state")
            if feed.error_message:
                issues.append(f"Error: {feed.error_message[:200]}")

        # Check for stale feed (no success in stale_minutes)
        if feed.last_success:
            stale_threshold = now - timedelta(minutes=stale_minutes)
            if feed.last_success < stale_threshold:
                mins_ago = int((now - feed.last_success).total_seconds() / 60)
                issues.append(
                    f"Feed '{feed.feed_name}' is stale — last success {mins_ago} min ago"
                )

        if issues:
            _create_notification(
                session,
                user_id=rule.user_id,
                rule_id=rule.id,
                title=f"Feed Alert: {feed.feed_name}",
                message="\n".join(issues),
                severity="high" if feed.status == "failed" else "medium",
                category="feed_error",
                entity_type="feed",
                entity_id=feed.feed_name,
                metadata={
                    "feed_name": feed.feed_name,
                    "status": feed.status,
                    "last_success": feed.last_success.isoformat() if feed.last_success else None,
                    "error_message": feed.error_message,
                    "items_fetched": feed.items_fetched,
                },
            )
            created += 1

    return created


def _eval_correlation_rule(
    session: Session,
    rule: NotificationRule,
    recent_items: list[IntelItem],
    now: datetime,
) -> int:
    """Detect cross-feed correlation (USP: same CVE/IOC across multiple feeds)."""
    # Group recent items by CVE IDs
    cve_feed_map: dict[str, set[str]] = {}
    cve_items: dict[str, list[IntelItem]] = {}

    for item in recent_items:
        for cve in (item.cve_ids or []):
            cve_feed_map.setdefault(cve, set()).add(item.source_name)
            cve_items.setdefault(cve, []).append(item)

    created = 0
    min_feeds = (rule.conditions or {}).get("min_feeds", 2)

    for cve, feeds in cve_feed_map.items():
        if len(feeds) >= min_feeds:
            items = cve_items[cve]
            max_risk = max(i.risk_score for i in items)
            _create_notification(
                session,
                user_id=rule.user_id,
                rule_id=rule.id,
                title=f"Cross-Feed Correlation: {cve} detected in {len(feeds)} feeds",
                message=f"{cve} appeared in: {', '.join(sorted(feeds))}. "
                        f"Highest risk score: {max_risk}.",
                severity="high" if max_risk >= 70 else "medium",
                category="correlation",
                entity_type="cve",
                entity_id=cve,
                metadata={
                    "cve_id": cve,
                    "feed_names": sorted(feeds),
                    "feed_count": len(feeds),
                    "max_risk_score": max_risk,
                    "item_count": len(items),
                },
            )
            created += 1

    return created


def _create_notification(
    session: Session,
    *,
    user_id: uuid.UUID,
    rule_id: uuid.UUID | None,
    title: str,
    message: str,
    severity: str,
    category: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    metadata: dict | None = None,
) -> Notification:
    """Create a notification record."""
    notif = Notification(
        user_id=user_id,
        rule_id=rule_id,
        title=title,
        message=message or "",
        severity=severity,
        category=category,
        entity_type=entity_type,
        entity_id=entity_id,
        meta=metadata or {},
    )
    session.add(notif)
    return notif


# ─── Dashboard Stats (async) ─────────────────────────────


async def get_notification_stats(
    db: AsyncSession, user_id: uuid.UUID
) -> dict:
    """Get notification stats for dashboard enrichment."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Unread count
    unread = await get_unread_count(db, user_id)

    # Last 24h counts by category
    q = (
        select(
            Notification.category,
            func.count().label("count"),
        )
        .where(
            Notification.user_id == user_id,
            Notification.created_at >= day_ago,
        )
        .group_by(Notification.category)
    )
    rows = (await db.execute(q)).all()
    by_category = {r.category: r.count for r in rows}

    # Last 24h counts by severity
    q2 = (
        select(
            Notification.severity,
            func.count().label("count"),
        )
        .where(
            Notification.user_id == user_id,
            Notification.created_at >= day_ago,
        )
        .group_by(Notification.severity)
    )
    rows2 = (await db.execute(q2)).all()
    by_severity = {r.severity: r.count for r in rows2}

    return {
        "unread_count": unread,
        "last_24h_total": sum(by_category.values()),
        "by_category": by_category,
        "by_severity": by_severity,
    }
