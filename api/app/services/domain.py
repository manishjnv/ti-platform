"""Domain & deployment configuration service.

Provides runtime domain configuration and deployment status for
the IntelWatch platform — used by the Settings page and health checks.
"""

from __future__ import annotations

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


def get_domain_config() -> dict:
    """Return the current domain and deployment configuration."""
    is_cf_configured = bool(settings.cf_access_team_name and settings.cf_access_aud)

    return {
        "platform_name": "IntelWatch - TI Platform",
        "version": "1.0.0",
        "environment": settings.environment,
        "domain": {
            "ui": settings.domain_ui,
            "api": settings.domain_api,
            "base": settings.domain,
        },
        "auth": {
            "method": "cloudflare_sso" if is_cf_configured else "local",
            "sso_configured": is_cf_configured,
            "cf_team_name": settings.cf_access_team_name if is_cf_configured else None,
        },
        "services": {
            "postgres": {"host": settings.postgres_host, "port": settings.postgres_port, "db": settings.postgres_db},
            "redis": {"url": settings.redis_url.split("@")[-1] if "@" in settings.redis_url else settings.redis_url},
            "opensearch": {"url": settings.opensearch_url},
        },
        "feeds": {
            "nvd": {"configured": True},
            "abuseipdb": {"configured": bool(settings.abuseipdb_api_key)},
            "otx": {"configured": bool(settings.otx_api_key)},
            "cisa_kev": {"configured": True},
            "urlhaus": {"configured": True},
        },
        "ai": {
            "enabled": settings.ai_enabled,
            "model": settings.ai_model if settings.ai_enabled else None,
        },
    }
