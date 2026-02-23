"""Base class for all feed connectors."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.logging import get_logger

logger = get_logger(__name__)


class BaseFeedConnector(ABC):
    """Base class providing retry, dedup, and state management."""

    FEED_NAME: str = ""
    SOURCE_RELIABILITY: int = 50

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60, follow_redirects=True)

    @abstractmethod
    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        """Fetch raw data from the source. Must be implemented by subclasses."""
        ...

    @abstractmethod
    def normalize(self, raw_items: list[dict]) -> list[dict]:
        """Normalize raw data into unified intel_items format."""
        ...

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=60))
    async def fetch_with_retry(self, last_cursor: str | None = None) -> list[dict]:
        """Fetch with exponential backoff retry."""
        return await self.fetch(last_cursor)

    def generate_hash(self, *parts: str) -> str:
        """Generate deterministic dedup hash."""
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    async def close(self):
        await self.client.aclose()
