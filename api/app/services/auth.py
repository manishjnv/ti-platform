"""Authentication service — JWT sessions, Google OAuth, and Email OTP.

Auth modes:
1. Google OAuth 2.0 — authorization code flow (redirect-based)
2. Email OTP — 6-digit code sent via SMTP, verified to create session
"""

from __future__ import annotations

import random
import smtplib
import uuid
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx
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


# ─── Google OAuth 2.0 (Authorization Code Flow) ─────────


GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


def get_google_redirect_uri() -> str:
    """Build the OAuth callback URL."""
    return f"{settings.domain_ui}/api/v1/auth/google/callback"


def get_google_auth_url(state: str = "") -> str:
    """Build the Google OAuth authorization URL."""
    import urllib.parse
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": get_google_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"


async def exchange_google_code(code: str) -> dict[str, Any] | None:
    """Exchange a Google authorization code for user info.

    1. Exchange code for access_token
    2. Fetch user info from Google
    Returns dict with email, name, picture or None on failure.
    """
    if not settings.google_client_id or not settings.google_client_secret:
        logger.error("google_oauth_not_configured")
        return None

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Step 1: Exchange code for tokens
            token_resp = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "code": code,
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "redirect_uri": get_google_redirect_uri(),
                    "grant_type": "authorization_code",
                },
            )
            if token_resp.status_code != 200:
                logger.error("google_token_exchange_failed", status=token_resp.status_code, body=token_resp.text[:200])
                return None

            tokens = token_resp.json()
            access_token = tokens.get("access_token")
            if not access_token:
                logger.error("google_no_access_token")
                return None

            # Step 2: Fetch user info
            userinfo_resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if userinfo_resp.status_code != 200:
                logger.error("google_userinfo_failed", status=userinfo_resp.status_code)
                return None

            userinfo = userinfo_resp.json()
            return {
                "email": userinfo["email"],
                "name": userinfo.get("name"),
                "picture": userinfo.get("picture"),
                "email_verified": userinfo.get("verified_email", False),
            }

    except Exception as e:
        logger.error("google_oauth_error", error=str(e))
        return None


# ─── Email OTP ──────────────────────────────────────────

OTP_TTL = 300  # 5 minutes
OTP_LENGTH = 6
OTP_COOLDOWN = 60  # 1 minute between sends


async def generate_otp(email: str) -> str | None:
    """Generate and store a 6-digit OTP for the given email.

    Returns the OTP string or None if rate-limited.
    """
    cooldown_key = f"otp_cooldown:{email}"
    if await redis_client.exists(cooldown_key):
        return None  # Rate limited

    code = "".join([str(random.randint(0, 9)) for _ in range(OTP_LENGTH)])

    # Store OTP in Redis
    otp_key = f"otp:{email}"
    await redis_client.set(otp_key, code, ex=OTP_TTL)
    await redis_client.set(cooldown_key, "1", ex=OTP_COOLDOWN)

    logger.info("otp_generated", email=email)
    return code


async def verify_otp(email: str, code: str) -> bool:
    """Verify an OTP code for the given email."""
    otp_key = f"otp:{email}"
    stored = await redis_client.get(otp_key)

    if not stored:
        return False

    if stored != code:
        return False

    # OTP is single-use — delete after successful verification
    await redis_client.delete(otp_key)
    await redis_client.delete(f"otp_cooldown:{email}")
    logger.info("otp_verified", email=email)
    return True


def send_otp_email(email: str, code: str) -> bool:
    """Send the OTP code via SMTP. Returns True on success."""
    if not settings.smtp_host or not settings.smtp_user:
        logger.error("smtp_not_configured")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"IntelWatch Login Code: {code}"
        msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
        msg["To"] = email

        text_body = f"""Your IntelWatch verification code is: {code}

This code expires in 5 minutes. If you didn't request this, ignore this email.

— IntelWatch Threat Intelligence Platform
"""

        html_body = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:480px;margin:40px auto;background:#111827;border-radius:16px;border:1px solid #1f2937;overflow:hidden;">
  <div style="padding:32px 32px 24px;text-align:center;">
    <div style="display:inline-block;padding:12px;background:rgba(59,130,246,0.1);border-radius:12px;margin-bottom:16px;">
      <span style="font-size:28px;">🛡️</span>
    </div>
    <h1 style="color:#f9fafb;font-size:20px;margin:0 0 4px;">IntelWatch</h1>
    <p style="color:#9ca3af;font-size:13px;margin:0;">Threat Intelligence Platform</p>
  </div>
  <div style="padding:0 32px 32px;text-align:center;">
    <p style="color:#d1d5db;font-size:14px;margin:0 0 20px;">Your verification code:</p>
    <div style="background:#1f2937;border:1px solid #374151;border-radius:12px;padding:20px;margin:0 0 20px;">
      <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#3b82f6;font-family:monospace;">{code}</span>
    </div>
    <p style="color:#6b7280;font-size:12px;margin:0;">Expires in 5 minutes. If you didn't request this, ignore this email.</p>
  </div>
</div>
</body>
</html>"""

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)

        logger.info("otp_email_sent", email=email)
        return True

    except Exception as e:
        logger.error("otp_email_failed", email=email, error=str(e))
        return False


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
