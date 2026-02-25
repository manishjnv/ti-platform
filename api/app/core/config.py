"""Application configuration via environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    secret_key: str = "change-me"
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000", "https://intelwatch.trendsmap.in"]

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "threat_intel"
    postgres_user: str = "ti_user"
    postgres_password: str = "changeme"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # OpenSearch
    opensearch_url: str = "https://localhost:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    opensearch_verify_certs: bool = False
    opensearch_index: str = "intel-items"

    # Feed keys
    nvd_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""

    # AI / Open-WebUI
    ai_api_url: str = "http://localhost:3000/api/chat/completions"
    ai_api_key: str = ""
    ai_model: str = "llama3"
    ai_timeout: int = 30
    ai_enabled: bool = True

    # Cloudflare Zero Trust
    cf_access_team_name: str = ""
    cf_access_aud: str = ""

    # Google OAuth
    google_client_id: str = ""

    # Domain configuration
    domain: str = "localhost"
    domain_ui: str = "http://localhost:3000"
    domain_api: str = "http://localhost:8000"

    # Auth / Session
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480  # 8 hours
    dev_bypass_auth: bool = False

    # Cache TTLs (seconds)
    cache_ttl_search: int = 300
    cache_ttl_dashboard: int = 60
    cache_ttl_ai_summary: int = 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()
