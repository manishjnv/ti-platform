"""Shared test fixtures for the IntelWatch API test suite.

Provides:
  - mock_user: fake User object for auth bypass
  - async_client: httpx.AsyncClient wired to the FastAPI app
  - Dependency overrides for get_db, get_current_user, require_viewer/analyst/admin
  - Mock Redis to prevent real connections
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# ── Mock User ────────────────────────────────────────────

class MockUser:
    """Minimal User stand-in matching SQLAlchemy model attributes."""

    def __init__(self, role: str = "admin"):
        self.id = "00000000-0000-0000-0000-000000000001"
        self.email = "test@intelwatch.local"
        self.name = "Test User"
        self.role = role
        self.is_active = True
        self.avatar_url = None
        self.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.last_login = datetime.now(timezone.utc)


# ── App + dependency overrides ───────────────────────────

@pytest.fixture()
def mock_user():
    return MockUser(role="admin")


@pytest.fixture(autouse=True)
def _mock_redis():
    """Patch the Redis client to prevent real connections in tests."""
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = True
    with patch("app.core.redis.redis_client", mock_redis):
        yield


@pytest.fixture()
async def async_client(mock_user) -> AsyncGenerator[AsyncClient, None]:
    """Create an httpx.AsyncClient that talks to the FastAPI app
    with auth and DB dependencies overridden."""

    # Import lazily to avoid module-level side effects
    from app.main import app
    from app.core.database import get_db
    from app.middleware.auth import (
        get_current_user,
        require_viewer,
        require_analyst,
        require_admin,
    )

    # Patch auth deps to return mock user
    app.dependency_overrides[get_current_user] = lambda: mock_user
    app.dependency_overrides[require_viewer] = lambda: mock_user
    app.dependency_overrides[require_analyst] = lambda: mock_user
    app.dependency_overrides[require_admin] = lambda: mock_user

    # Mock DB session that supports common SQLAlchemy result patterns:
    #   result = await db.execute(query)
    #   result.scalars().all()  -> []
    #   result.scalars().first()  -> None
    #   result.scalar()  -> 0
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalars.return_value.first.return_value = None
    mock_result.scalar.return_value = 0
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalar_one.return_value = 0
    mock_db.execute.return_value = mock_result

    app.dependency_overrides[get_db] = lambda: mock_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    # Cleanup
    app.dependency_overrides.clear()
