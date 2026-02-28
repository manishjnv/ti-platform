"""FastAPI application — IntelWatch TI Platform API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import setup_logging
from app.routes import health, intel, search, dashboard, admin, auth, techniques, graph, notifications, reports, iocs
from app.routes import settings as settings_route

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
    title="IntelWatch - TI Platform",
    description="IntelWatch Threat Intelligence Platform API — live threat intel feeds, IOC search, risk scoring, analytics",
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
app.include_router(auth.router, prefix=PREFIX)
app.include_router(intel.router, prefix=PREFIX)
app.include_router(search.router, prefix=PREFIX)
app.include_router(dashboard.router, prefix=PREFIX)
app.include_router(admin.router, prefix=PREFIX)
app.include_router(techniques.router, prefix=PREFIX)
app.include_router(graph.router, prefix=PREFIX)
app.include_router(notifications.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(iocs.router, prefix=PREFIX)
app.include_router(settings_route.router, prefix=PREFIX)


@app.get("/")
async def root():
    return {"message": "IntelWatch - TI Platform API", "version": "1.0.0"}
