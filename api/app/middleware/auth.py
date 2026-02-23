"""Authentication middleware — trusts Cloudflare Access identity headers.

In development mode, allows bypass with configurable test user.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models.models import User

logger = get_logger(__name__)
settings = get_settings()

# Cloudflare Access headers
CF_ACCESS_EMAIL = "cf-access-authenticated-user-email"
CF_ACCESS_JWT = "cf-access-jwt-assertion"


async def get_or_create_user(db: AsyncSession, email: str, name: str | None = None) -> User:
    """Find existing user or create a new viewer."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user:
        user.last_login = datetime.now(timezone.utc)
        await db.flush()
        return user

    user = User(
        id=uuid.uuid4(),
        email=email,
        name=name or email.split("@")[0],
        role="viewer",
        last_login=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.flush()
    logger.info("new_user_created", email=email)
    return user


async def get_current_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Extract user from Cloudflare Access headers or dev bypass."""

    # Development bypass
    if settings.environment == "development":
        email = request.headers.get(CF_ACCESS_EMAIL, "dev@localhost")
        return await get_or_create_user(db, email, "Developer")

    # Production: require Cloudflare Access headers
    email = request.headers.get(CF_ACCESS_EMAIL)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Cloudflare Access authentication",
        )

    user = await get_or_create_user(db, email)
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


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
