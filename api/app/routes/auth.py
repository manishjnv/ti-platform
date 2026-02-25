"""Authentication routes — login, logout, session management.

Supports:
1. Google OAuth (production) — validates Google ID token
2. Cloudflare Zero Trust callback — validates CF Access headers
3. Development login — auto-creates dev user session
4. Session refresh and logout
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.middleware.audit import log_audit
from app.schemas import UserResponse
from pydantic import BaseModel

from app.services.auth import (
    create_session,
    decode_access_token,
    get_or_create_user,
    is_session_valid,
    revoke_session,
    verify_cf_access_token,
    verify_google_token,
)

logger = get_logger(__name__)
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_NAME = "iw_session"
COOKIE_MAX_AGE = settings.jwt_expire_minutes * 60


def _set_session_cookie(response: Response, token: str) -> None:
    """Set the session cookie with secure defaults."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    """Clear the session cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")


@router.post("/login")
async def login(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Login endpoint.

    In production: validates Cloudflare Access JWT from headers.
    In development: creates a dev user session automatically.
    """
    # ── Development bypass ──
    if settings.environment == "development" or settings.dev_bypass_auth:
        user = await get_or_create_user(db, "dev@intelwatch.local", "Developer", "admin")
        token = await create_session(user)
        _set_session_cookie(response, token)

        await log_audit(
            db,
            user_id=str(user.id),
            action="login",
            details={"method": "dev_bypass"},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        return {
            "status": "authenticated",
            "user": UserResponse.model_validate(user).model_dump(),
        }

    # ── Production: Cloudflare Zero Trust SSO (fallback) ──
    cf_jwt = request.headers.get("cf-access-jwt-assertion")
    cf_email = request.headers.get("cf-access-authenticated-user-email")

    if cf_jwt and cf_email:
        cf_payload = await verify_cf_access_token(cf_jwt)
        if cf_payload:
            user = await get_or_create_user(db, cf_email)
            token = await create_session(user)
            _set_session_cookie(response, token)

            await log_audit(
                db,
                user_id=str(user.id),
                action="login",
                details={"method": "cloudflare_sso", "cf_email": cf_email},
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )

            return {
                "status": "authenticated",
                "user": UserResponse.model_validate(user).model_dump(),
            }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use Google Sign-In or access via SSO.",
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Logout — revoke session and clear cookie."""
    token = request.cookies.get(COOKIE_NAME)
    if token:
        payload = decode_access_token(token)
        if payload and payload.get("sid"):
            await revoke_session(payload["sid"])

            await log_audit(
                db,
                user_id=payload.get("sub"),
                action="logout",
                ip_address=request.client.host if request.client else None,
            )

    _clear_session_cookie(response)
    return {"status": "logged_out"}


@router.get("/session")
async def check_session(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Check if the current session is valid. Returns user info if authenticated."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No active session",
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    # Verify session hasn't been revoked
    sid = payload.get("sid")
    if sid and not await is_session_valid(sid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked",
        )

    # Fetch fresh user data
    user = await get_or_create_user(db, payload["email"], payload.get("name"))
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return {
        "status": "authenticated",
        "user": UserResponse.model_validate(user).model_dump(),
    }


class GoogleLoginRequest(BaseModel):
    credential: str


@router.post("/google")
async def google_login(
    body: GoogleLoginRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Login via Google OAuth — verify Google ID token and create session."""
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth is not configured",
        )

    google_info = verify_google_token(body.credential, settings.google_client_id)
    if not google_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google token",
        )

    email = google_info["email"]
    name = google_info.get("name", email.split("@")[0])

    user = await get_or_create_user(db, email, name)
    token = await create_session(user)
    _set_session_cookie(response, token)

    await log_audit(
        db,
        user_id=str(user.id),
        action="login",
        details={"method": "google_oauth", "email": email},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return {
        "status": "authenticated",
        "user": UserResponse.model_validate(user).model_dump(),
    }


@router.get("/config")
async def auth_config():
    """Return auth configuration for the frontend.

    Tells the UI which authentication method is active
    so it can render the appropriate login flow.
    """
    is_google_configured = bool(settings.google_client_id)
    is_cf_configured = bool(settings.cf_access_team_name and settings.cf_access_aud)

    if is_google_configured:
        auth_method = "google"
    elif is_cf_configured:
        auth_method = "cloudflare_sso"
    else:
        auth_method = "local"

    return {
        "auth_method": auth_method,
        "google_client_id": settings.google_client_id if is_google_configured else None,
        "cf_team_domain": f"https://{settings.cf_access_team_name}.cloudflareaccess.com" if is_cf_configured else None,
        "app_name": "IntelWatch - TI Platform",
        "environment": settings.environment,
        "dev_bypass": settings.dev_bypass_auth or settings.environment == "development",
    }
