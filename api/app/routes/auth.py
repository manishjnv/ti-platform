"""Authentication routes — Google OAuth, Email OTP, session management.

Supports:
1. Google OAuth 2.0 — authorization code flow (redirect-based)
2. Email OTP — 6-digit code sent via SMTP
3. Session check, refresh, and logout
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
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
    exchange_google_code,
    generate_otp,
    get_google_auth_url,
    get_or_create_user,
    is_session_valid,
    revoke_session,
    send_otp_email,
    verify_otp,
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
        secure=True,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    """Clear the session cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")


# ─── Google OAuth 2.0 (Authorization Code Flow) ─────────


@router.get("/google/url")
async def google_auth_url():
    """Return the Google OAuth authorization URL for the frontend to redirect to."""
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth is not configured",
        )

    import secrets
    state = secrets.token_urlsafe(32)
    url = get_google_auth_url(state=state)
    return {"url": url, "state": state}


@router.get("/google/callback")
async def google_callback(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    code: str = "",
    error: str = "",
):
    """Handle the Google OAuth callback.

    Google redirects here with ?code=... after user consents.
    We exchange the code for user info, create session, and redirect to dashboard.
    """
    if error:
        logger.warning("google_oauth_denied", error=error)
        return RedirectResponse(url="/login?error=oauth_denied")

    if not code:
        return RedirectResponse(url="/login?error=no_code")

    google_info = await exchange_google_code(code)
    if not google_info:
        return RedirectResponse(url="/login?error=oauth_failed")

    email = google_info["email"]
    name = google_info.get("name", email.split("@")[0])

    user = await get_or_create_user(db, email, name)
    token = await create_session(user)

    # Build redirect response and set cookie
    redirect = RedirectResponse(url="/dashboard", status_code=302)
    redirect.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )

    await log_audit(
        db,
        user_id=str(user.id),
        action="login",
        details={"method": "google_oauth", "email": email},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    logger.info("google_login_success", email=email)
    return redirect


# ─── Email OTP ──────────────────────────────────────────


class OTPSendRequest(BaseModel):
    email: str


class OTPVerifyRequest(BaseModel):
    email: str
    code: str


@router.post("/otp/send")
async def otp_send(body: OTPSendRequest):
    """Send a one-time login code to the given email address."""
    if not settings.email_otp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email OTP login is not enabled",
        )

    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email address",
        )

    code = await generate_otp(email)
    if code is None:
        # Rate limited — but we still return success to avoid email enumeration
        return {"status": "sent", "message": "If the email is valid, a code was sent."}

    sent = send_otp_email(email, code)
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email. Please try again.",
        )

    return {"status": "sent", "message": "Verification code sent to your email."}


@router.post("/otp/verify")
async def otp_verify(
    body: OTPVerifyRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify an email OTP code and create a session."""
    email = body.email.strip().lower()
    code = body.code.strip()

    if not await verify_otp(email, code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired code",
        )

    user = await get_or_create_user(db, email)
    token = await create_session(user)
    _set_session_cookie(response, token)

    await log_audit(
        db,
        user_id=str(user.id),
        action="login",
        details={"method": "email_otp", "email": email},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    logger.info("otp_login_success", email=email)
    return {
        "status": "authenticated",
        "user": UserResponse.model_validate(user).model_dump(),
    }


# ─── Session Management ────────────────────────────────


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


@router.get("/config")
async def auth_config():
    """Return auth configuration for the frontend.

    Tells the UI which authentication methods are available
    so it can render the appropriate login options.
    """
    return {
        "google_configured": bool(settings.google_client_id and settings.google_client_secret),
        "email_otp_enabled": settings.email_otp_enabled,
        "app_name": "IntelWatch - Threat Intelligence Platform",
    }
