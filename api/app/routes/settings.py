"""Platform settings endpoints — user preferences + API key status."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.models import User, UserSetting, FeedSyncState
from app.schemas import UserSettingsResponse, UserSettingsUpdate

router = APIRouter(prefix="/settings", tags=["settings"])
settings = get_settings()

# ─── Default settings values ─────────────────────────────
DEFAULTS: dict = {
    # General
    "platform_name": "IntelWatch",
    "timezone": "UTC",
    "default_risk_threshold": 70,
    "auto_refresh": True,
    # Security
    "api_auth_required": True,
    "session_timeout": "4 hours",
    "rate_limit": 100,
    "pii_redaction": True,
    # Appearance
    "theme": "dark",
    "compact_mode": False,
    "show_risk_scores": True,
    # Data
    "data_retention": "never",
    "deduplication": True,
    "opensearch_sync": True,
}


@router.get("", response_model=UserSettingsResponse)
async def get_user_settings(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get current user's settings (merged with defaults)."""
    result = await db.execute(
        select(UserSetting).where(UserSetting.user_id == user.id)
    )
    row = result.scalar_one_or_none()
    merged = {**DEFAULTS}
    if row and row.preferences:
        merged.update(row.preferences)
    return UserSettingsResponse(settings=merged)


@router.put("", response_model=UserSettingsResponse)
async def update_user_settings(
    body: UserSettingsUpdate,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update current user's settings."""
    result = await db.execute(
        select(UserSetting).where(UserSetting.user_id == user.id)
    )
    row = result.scalar_one_or_none()
    if row:
        existing = row.preferences or {}
        existing.update(body.settings)
        row.preferences = existing
        # Force SQLAlchemy to detect change on JSONB
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(row, "preferences")
    else:
        row = UserSetting(user_id=user.id, preferences=body.settings)
        db.add(row)

    await db.commit()

    merged = {**DEFAULTS}
    if row.preferences:
        merged.update(row.preferences)
    return UserSettingsResponse(settings=merged)


@router.get("/api-keys")
async def get_api_key_status(
    user: Annotated[User, Depends(get_current_user)],
):
    """Get the live configured/missing status of all external API keys."""
    keys = [
        {
            "name": "AbuseIPDB",
            "configured": bool(settings.abuseipdb_api_key),
            "masked": _mask(settings.abuseipdb_api_key),
        },
        {
            "name": "OTX (AlienVault)",
            "configured": bool(settings.otx_api_key),
            "masked": _mask(settings.otx_api_key),
        },
        {
            "name": "VirusTotal",
            "configured": bool(settings.virustotal_api_key),
            "masked": _mask(settings.virustotal_api_key),
        },
        {
            "name": "Shodan",
            "configured": bool(settings.shodan_api_key),
            "masked": _mask(settings.shodan_api_key),
        },
        {
            "name": "NVD",
            "configured": bool(settings.nvd_api_key),
            "masked": _mask(settings.nvd_api_key),
        },
        {
            "name": "AI / LLM",
            "configured": bool(settings.ai_enabled and settings.ai_api_key),
            "masked": _mask(settings.ai_api_key) if settings.ai_enabled else "Disabled",
            "model": settings.ai_model if settings.ai_enabled else None,
        },
    ]
    configured_count = sum(1 for k in keys if k["configured"])
    return {"keys": keys, "configured_count": configured_count, "total_count": len(keys)}


@router.get("/platform-info")
async def get_platform_info(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get platform info: version, environment, service health summary."""
    feeds_result = await db.execute(select(FeedSyncState))
    feeds = feeds_result.scalars().all()
    active_feeds = sum(1 for f in feeds if f.status in ("success", "running"))

    return {
        "version": "1.0.0",
        "environment": settings.environment,
        "domain": settings.domain,
        "domain_ui": settings.domain_ui,
        "domain_api": settings.domain_api,
        "ai_enabled": settings.ai_enabled,
        "ai_model": settings.ai_model if settings.ai_enabled else None,
        "total_feeds": len(feeds),
        "active_feeds": active_feeds,
    }


def _mask(key: str) -> str:
    """Mask an API key, showing only last 4 chars."""
    if not key:
        return "Not configured"
    if len(key) <= 8:
        return "••••" + key[-2:]
    return "••••••••••" + key[-4:]
