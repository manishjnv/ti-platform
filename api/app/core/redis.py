"""Redis client and caching utilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

redis_client = aioredis.from_url(
    settings.redis_url,
    decode_responses=True,
    max_connections=20,
)


def cache_key(prefix: str, *args: Any) -> str:
    raw = f"{prefix}:" + ":".join(str(a) for a in args)
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


async def get_cached(key: str) -> dict | list | None:
    data = await redis_client.get(key)
    if data:
        return json.loads(data)
    return None


async def set_cached(key: str, value: Any, ttl: int = 300) -> None:
    await redis_client.set(key, json.dumps(value, default=str), ex=ttl)


async def invalidate_pattern(pattern: str) -> None:
    keys = []
    async for key in redis_client.scan_iter(match=pattern):
        keys.append(key)
    if keys:
        await redis_client.delete(*keys)
