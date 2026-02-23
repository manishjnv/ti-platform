"""FastAPI application — Threat Intelligence Platform API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.routes import health, intel, search, dashboard, admin

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    # Startup: ensure OpenSearch index exists
    try:
        from app.core.opensearch import ensure_index
        ensure_index()
    except Exception:
        pass  # Non-fatal on startup

    yield

    # Shutdown
    from app.core.redis import redis_client
    await redis_client.close()


app = FastAPI(
    title="Threat Intelligence Platform",
    description="Phase-1 TI Platform API — live threat intel feed, search, scoring",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.environment != "production" else None,
    redoc_url="/api/redoc" if settings.environment != "production" else None,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes
PREFIX = settings.api_prefix
app.include_router(health.router, prefix=PREFIX)
app.include_router(intel.router, prefix=PREFIX)
app.include_router(search.router, prefix=PREFIX)
app.include_router(dashboard.router, prefix=PREFIX)
app.include_router(admin.router, prefix=PREFIX)


@app.get("/")
async def root():
    return {"message": "Threat Intelligence Platform API", "version": "1.0.0"}
