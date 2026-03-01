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
    cors_origins: list[str] = ["http://localhost:3000", "https://intelwatch.in"]

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
    ipinfo_token: str = ""  # IPinfo Lite — free tier (50k/month)

    # AI — OpenAI-compatible endpoint (Groq, Google Gemini, OpenAI, etc.)
    ai_api_url: str = "https://api.groq.com/openai/v1/chat/completions"
    ai_api_key: str = ""
    ai_model: str = "llama-3.3-70b-versatile"
    ai_timeout: int = 30
    ai_enabled: bool = True

    # Google OAuth
    google_client_id: str = ""
    google_client_secret: str = ""

    # Email OTP (SMTP)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@intelwatch.in"
    smtp_from_name: str = "IntelWatch"
    email_otp_enabled: bool = False

    # Domain configuration
    domain: str = "intelwatch.in"
    domain_ui: str = "https://intelwatch.in"
    domain_api: str = "https://intelwatch.in"

    # Auth / Session
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480  # 8 hours

    # Cache TTLs (seconds)
    cache_ttl_search: int = 300
    cache_ttl_dashboard: int = 60
    cache_ttl_ai_summary: int = 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()
