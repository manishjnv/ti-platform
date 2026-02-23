"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import get_settings
from app.core.redis import redis_client
from app.core.opensearch import opensearch_client
from app.schemas import HealthResponse

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    pg_ok = False
    redis_ok = False
    os_ok = False

    # PostgreSQL
    try:
        from app.core.database import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        pg_ok = True
    except Exception:
        pass

    # Redis
    try:
        await redis_client.ping()
        redis_ok = True
    except Exception:
        pass

    # OpenSearch
    try:
        os_ok = opensearch_client.ping()
    except Exception:
        pass

    return HealthResponse(
        status="ok" if (pg_ok and redis_ok) else "degraded",
        version="1.0.0",
        postgres=pg_ok,
        redis=redis_ok,
        opensearch=os_ok,
        environment=settings.environment,
    )
