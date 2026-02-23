"""Authentication middleware — JWT session-based auth with Cloudflare Access fallback.

Supports:
1. JWT session cookie (iw_session) — primary auth method
2. Cloudflare Access headers — auto-creates session on first request
3. Development bypass — auto-authenticates as dev user
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models.models import User
from app.services.auth import (
    decode_access_token,
    get_or_create_user,
    is_session_valid,
)

logger = get_logger(__name__)
settings = get_settings()

COOKIE_NAME = "iw_session"

# Cloudflare Access headers
CF_ACCESS_EMAIL = "cf-access-authenticated-user-email"
CF_ACCESS_JWT = "cf-access-jwt-assertion"


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Extract user from JWT session cookie, CF Access headers, or dev bypass.

    Priority:
    1. JWT session cookie (iw_session)
    2. Cloudflare Access headers (cf-access-authenticated-user-email)
    3. Development bypass (if enabled)
    """

    # ── 1. Check JWT session cookie ──
    token = request.cookies.get(COOKIE_NAME)
    if token:
        payload = decode_access_token(token)
        if payload:
            # Verify session hasn't been revoked
            sid = payload.get("sid")
            if sid and await is_session_valid(sid):
                user = await get_or_create_user(db, payload["email"], payload.get("name"))
                if user.is_active:
                    return user

    # ── 2. Cloudflare Access headers (production SSO) ──
    cf_email = request.headers.get(CF_ACCESS_EMAIL)
    if cf_email:
        user = await get_or_create_user(db, cf_email)
        if user.is_active:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # ── 3. Development bypass ──
    if settings.environment == "development" or settings.dev_bypass_auth:
        return await get_or_create_user(db, "dev@intelwatch.local", "Developer", "admin")

    # ── No auth found ──
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please login at /login.",
    )


def require_role(*roles: str):
    """Dependency factory: require user has one of the specified roles."""

    async def checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(roles)}",
            )
        return user

    return checker


# Convenience role dependencies
require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")
require_viewer = require_role("admin", "analyst", "viewer")
