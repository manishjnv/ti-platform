"""AI summarization service — uses Open-WebUI compatible API.

Features:
  - Async HTTP calls
  - Redis caching for summaries
  - Timeout fallback
  - Graceful "AI unavailable" state
"""

from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import cache_key, get_cached, set_cached

logger = get_logger(__name__)
settings = get_settings()


async def generate_summary(
    title: str,
    description: str | None = None,
    severity: str = "unknown",
    source_name: str = "",
    cve_ids: list[str] | None = None,
) -> str | None:
    """Generate an AI summary for a threat intel item.

    Returns None if AI is unavailable or disabled.
    """
    if not settings.ai_enabled:
        return None

    # Check cache first
    ck = cache_key("ai_summary", title, severity)
    cached = await get_cached(ck)
    if cached:
        return cached.get("summary")

    prompt = _build_prompt(title, description, severity, source_name, cve_ids or [])

    try:
        async with httpx.AsyncClient(timeout=settings.ai_timeout) as client:
            headers = {"Content-Type": "application/json"}
            if settings.ai_api_key:
                headers["Authorization"] = f"Bearer {settings.ai_api_key}"

            payload = {
                "model": settings.ai_model,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity threat intelligence analyst. "
                            "Provide a concise 2-3 sentence summary of the following "
                            "threat intelligence item. Focus on impact, affected systems, "
                            "and recommended actions. Be direct and technical."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 200,
                "temperature": 0.3,
            }

            response = await client.post(settings.ai_api_url, json=payload, headers=headers)
            response.raise_for_status()

            data = response.json()
            choices = data.get("choices", [])
            if choices:
                summary = choices[0].get("message", {}).get("content", "").strip()
                if summary:
                    await set_cached(ck, {"summary": summary}, ttl=settings.cache_ttl_ai_summary)
                    return summary

    except httpx.TimeoutException:
        logger.warning("ai_timeout", title=title[:100])
    except httpx.HTTPStatusError as e:
        logger.warning("ai_http_error", status=e.response.status_code)
    except Exception as e:
        logger.warning("ai_error", error=str(e))

    return None


def _build_prompt(
    title: str,
    description: str | None,
    severity: str,
    source_name: str,
    cve_ids: list[str],
) -> str:
    parts = [f"Title: {title}", f"Severity: {severity}"]
    if description:
        parts.append(f"Description: {description[:1000]}")
    if source_name:
        parts.append(f"Source: {source_name}")
    if cve_ids:
        parts.append(f"CVE IDs: {', '.join(cve_ids[:5])}")
    return "\n".join(parts)


async def check_ai_health() -> bool:
    """Quick health check for AI service."""
    if not settings.ai_enabled:
        return False
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            # Try a simple models endpoint
            headers = {}
            if settings.ai_api_key:
                headers["Authorization"] = f"Bearer {settings.ai_api_key}"
            base = settings.ai_api_url.rsplit("/", 1)[0]  # Remove /completions
            response = await client.get(f"{base}/models", headers=headers)
            return response.status_code == 200
    except Exception:
        return False
