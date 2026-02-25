"""Authentication service — JWT session management, Google OAuth, and Cloudflare Zero Trust.

Supports three auth modes:
1. Google OAuth (production) — validates Google ID token from frontend
2. Cloudflare Zero Trust SSO — validates CF Access JWT headers
3. Local JWT sessions (development) — dev bypass login

All modes produce a platform JWT stored as an HttpOnly cookie.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import redis_client
from app.models.models import User

logger = get_logger(__name__)
settings = get_settings()

# ─── JWT Token Management ────────────────────────────────


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc), "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decode and verify a JWT token. Returns claims or None."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        return None


# ─── Session Management (Redis-backed) ──────────────────


async def create_session(user: User) -> str:
    """Create a session token for a user and store in Redis."""
    session_id = str(uuid.uuid4())
    token = create_access_token({
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "name": user.name or user.email.split("@")[0],
        "sid": session_id,
    })

    # Store session in Redis for server-side validation / revocation
    await redis_client.set(
        f"session:{session_id}",
        str(user.id),
        ex=settings.jwt_expire_minutes * 60,
    )

    logger.info("session_created", user_email=user.email, session_id=session_id)
    return token


async def revoke_session(session_id: str) -> None:
    """Revoke a session by removing from Redis."""
    await redis_client.delete(f"session:{session_id}")
    logger.info("session_revoked", session_id=session_id)


async def is_session_valid(session_id: str) -> bool:
    """Check if a session is still active in Redis."""
    return await redis_client.exists(f"session:{session_id}") > 0


# ─── Google OAuth Token Verification ─────────────────────


def verify_google_token(token: str, client_id: str) -> dict[str, Any] | None:
    """Verify a Google ID token from the frontend Sign-In flow.

    Returns user info dict with 'email', 'name', 'picture', etc. or None on failure.
    """
    try:
        idinfo = google_id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            client_id,
        )
        # Token is valid — return user info
        return {
            "email": idinfo["email"],
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture"),
            "email_verified": idinfo.get("email_verified", False),
        }
    except Exception as e:
        logger.error("google_token_verify_failed", error=str(e))
        return None


# ─── Cloudflare Zero Trust JWT Verification ──────────────


async def verify_cf_access_token(token: str) -> dict[str, Any] | None:
    """Verify a Cloudflare Access JWT assertion.

    Fetches the team's public keys and validates the token.
    Returns the decoded payload or None on failure.
    """
    if not settings.cf_access_team_name or not settings.cf_access_aud:
        return None

    certs_url = f"https://{settings.cf_access_team_name}.cloudflareaccess.com/cdn-cgi/access/certs"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(certs_url)
            resp.raise_for_status()
            certs = resp.json()

        # Try each public key
        for key in certs.get("public_certs", []):
            try:
                payload = jwt.decode(
                    token,
                    key["cert"],
                    algorithms=["RS256"],
                    audience=settings.cf_access_aud,
                )
                return payload
            except JWTError:
                continue

    except Exception as e:
        logger.error("cf_access_verify_failed", error=str(e))

    return None


# ─── User Resolution ────────────────────────────────────


async def get_or_create_user(
    db: AsyncSession,
    email: str,
    name: str | None = None,
    role: str = "viewer",
) -> User:
    """Find existing user or create a new one."""
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
        role=role,
        last_login=datetime.now(timezone.utc),
    )
    db.add(user)
    await db.flush()
    logger.info("new_user_created", email=email, role=role)
    return user
