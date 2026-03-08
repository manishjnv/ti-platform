"""AI summarization service — uses OpenAI-compatible API with multi-provider fallback.

Supports: Groq, Cerebras, Google Gemini, OpenAI, Open-WebUI, etc.

Features:
  - Async HTTP calls with automatic fallback on rate-limit (429)
  - Multi-provider chain: Groq → Cerebras → Groq alt models
  - Redis caching for summaries
  - Timeout fallback
  - Custom system prompts per use-case
  - Graceful "AI unavailable" state
  - DB-managed settings (admin-configurable via UI)
  - Per-feature toggles and daily limits
"""

from __future__ import annotations

from app.prompts import (
    INTEL_SUMMARY_PROMPT,
    JSON_REPAIR_PROMPT,
)


import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import cache_key, get_cached, set_cached, redis_client

logger = get_logger(__name__)
settings = get_settings()

_DAILY_KEY_PREFIX = "ai_daily_usage"


# ── DB-backed AI Settings Cache ───────────────────────────

_db_settings_cache: dict | None = None
_db_settings_ts: float = 0


async def get_ai_db_settings() -> dict | None:
    """Load AI settings from Redis cache (set by the route on save).

    Falls back to DB query on cold start, then caches for 60s.
    Returns None if no DB settings exist (use env defaults).
    """
    global _db_settings_cache, _db_settings_ts
    import time

    now = time.time()
    if _db_settings_cache is not None and (now - _db_settings_ts) < 60:
        return _db_settings_cache

    # Try Redis cache first
    cached = await get_cached("ai_settings_cache")
    if cached and isinstance(cached, dict):
        _db_settings_cache = cached
        _db_settings_ts = now
        return cached

    # Cold start — query DB directly
    try:
        from app.core.database import async_session_factory
        from app.models.models import AISetting
        from sqlalchemy import select

        async with async_session_factory() as db:
            result = await db.execute(select(AISetting).where(AISetting.key == "default"))
            row = result.scalar_one_or_none()
            if not row:
                return None

            data = {
                "ai_enabled": row.ai_enabled,
                "primary_api_url": row.primary_api_url,
                "primary_api_key": row.primary_api_key,
                "primary_model": row.primary_model,
                "primary_timeout": row.primary_timeout,
                "primary_provider": row.primary_provider,
                "fallback_providers": row.fallback_providers or [],
                "feature_intel_summary": row.feature_intel_summary,
                "feature_intel_enrichment": row.feature_intel_enrichment,
                "feature_news_enrichment": row.feature_news_enrichment,
                "feature_live_lookup": row.feature_live_lookup,
                "feature_report_gen": row.feature_report_gen,
                "feature_briefing_gen": row.feature_briefing_gen,
                "daily_limit_intel_summary": row.daily_limit_intel_summary,
                "daily_limit_intel_enrichment": row.daily_limit_intel_enrichment,
                "daily_limit_news_enrichment": row.daily_limit_news_enrichment,
                "daily_limit_live_lookup": row.daily_limit_live_lookup,
                "daily_limit_report_gen": row.daily_limit_report_gen,
                "daily_limit_briefing_gen": row.daily_limit_briefing_gen,
                "prompt_intel_summary": row.prompt_intel_summary,
                "prompt_intel_enrichment": row.prompt_intel_enrichment,
                "prompt_news_enrichment": row.prompt_news_enrichment,
                "prompt_live_lookup": row.prompt_live_lookup,
                "prompt_report_gen": row.prompt_report_gen,
                "prompt_briefing_gen": row.prompt_briefing_gen,
                "default_temperature": row.default_temperature,
                "default_max_tokens": row.default_max_tokens,
                "requests_per_minute": row.requests_per_minute,
                "batch_delay_ms": row.batch_delay_ms,
                "cache_ttl_summary": row.cache_ttl_summary,
                "cache_ttl_enrichment": row.cache_ttl_enrichment,
                "cache_ttl_lookup": row.cache_ttl_lookup,
                "model_intel_summary": row.model_intel_summary,
                "model_intel_enrichment": row.model_intel_enrichment,
                "model_news_enrichment": row.model_news_enrichment,
                "model_live_lookup": row.model_live_lookup,
                "model_report_gen": row.model_report_gen,
                "model_briefing_gen": row.model_briefing_gen,
            }
            await set_cached("ai_settings_cache", data, ttl=60)
            _db_settings_cache = data
            _db_settings_ts = now
            return data
    except Exception as e:
        logger.debug("ai_db_settings_load_error", error=str(e))
        return None


async def is_feature_enabled(feature: str) -> bool:
    """Check if a specific AI feature is enabled (global + per-feature toggle)."""
    db_cfg = await get_ai_db_settings()
    if db_cfg is None:
        # No DB settings — fall back to env
        return settings.ai_enabled

    if not db_cfg.get("ai_enabled", True):
        return False

    return db_cfg.get(f"feature_{feature}", True)


async def check_daily_limit(feature: str) -> bool:
    """Check if the daily limit for a feature has been reached. Returns True if OK to proceed."""
    db_cfg = await get_ai_db_settings()
    if db_cfg is None:
        return True  # No limits when no DB settings

    limit = db_cfg.get(f"daily_limit_{feature}", 0)
    if limit <= 0:
        return True  # 0 = unlimited

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    r = redis_client
    count = await r.get(f"{_DAILY_KEY_PREFIX}:{feature}:{today}")
    return int(count or 0) < limit


async def increment_daily_usage(feature: str):
    """Increment the daily usage counter for a feature."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    r = redis_client
    key = f"{_DAILY_KEY_PREFIX}:{feature}:{today}"
    await r.incr(key)
    await r.expire(key, 86400)


_PROVIDER_USAGE_PREFIX = "ai_provider_usage"


async def _increment_provider_usage(provider_name: str):
    """Increment today's usage counter for a specific provider."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    r = redis_client
    key = f"{_PROVIDER_USAGE_PREFIX}:{provider_name}:{today}"
    await r.incr(key)
    await r.expire(key, 86400)


async def _get_provider_usage(provider_name: str) -> int:
    """Get today's usage count for a specific provider."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    r = redis_client
    count = await r.get(f"{_PROVIDER_USAGE_PREFIX}:{provider_name}:{today}")
    return int(count or 0)


async def get_custom_prompt(feature: str) -> str | None:
    """Get the custom prompt for a feature from DB settings, or None to use default."""
    db_cfg = await get_ai_db_settings()
    if db_cfg is None:
        return None
    return db_cfg.get(f"prompt_{feature}")


async def get_cache_ttl(feature: str) -> int:
    """Get the cache TTL for a feature from DB settings."""
    db_cfg = await get_ai_db_settings()
    defaults = {"summary": 3600, "enrichment": 21600, "lookup": 300}
    if db_cfg is None:
        return defaults.get(feature, 3600)
    return db_cfg.get(f"cache_ttl_{feature}", defaults.get(feature, 3600))


async def get_feature_model(feature: str) -> str | None:
    """Get per-feature model override from DB settings, or None to use primary."""
    db_cfg = await get_ai_db_settings()
    if db_cfg is None:
        return None
    model = db_cfg.get(f"model_{feature}", "")
    return model if model else None


# ── Fallback Model Chain ──────────────────────────────────
# Each entry is a (url, key_env_attr, model) tuple.  When the primary
# returns 429 (rate-limit), we cascade to the next provider/model.
# All providers use the OpenAI chat-completions interface.

@dataclass(frozen=True, slots=True)
class _Provider:
    name: str
    url: str
    key: str          # resolved API key (empty = skip)
    model: str
    timeout: int = 30


_fallback_chain: list[_Provider] | None = None
_chain_built_ts: float = 0


def _ensure_chat_url(u: str) -> str:
    """Normalize a base API URL to a full chat completions endpoint."""
    u = u.rstrip("/")
    # Gemini requires /openai/ in the path for OpenAI-compatible mode
    if "generativelanguage.googleapis.com" in u and "/openai" not in u:
        u = u.rstrip("/") + "/openai"
    if not u.endswith("/chat/completions"):
        u += "/chat/completions"
    return u


async def _get_chain_async() -> list[_Provider]:
    """Get the provider chain, always from DB settings. Rebuilds every 60s.

    The chain is ONLY built from DB ai_settings. If no DB settings exist
    and env vars are set, a minimal single-provider env fallback is used.
    No hardcoded alt-model or multi-provider env chains.
    """
    global _fallback_chain, _chain_built_ts
    import time

    now = time.time()
    if _fallback_chain is not None and (now - _chain_built_ts) < 60:
        return _fallback_chain

    db_cfg = await get_ai_db_settings()
    chain: list[_Provider] = []

    if db_cfg and db_cfg.get("primary_api_key"):
        # Build chain from DB settings — split comma-separated models
        # into separate chain entries (same provider, different model buckets)
        provider_name = db_cfg.get("primary_provider", "groq")
        primary_url = _ensure_chat_url(db_cfg["primary_api_url"])
        primary_key = db_cfg["primary_api_key"]
        primary_timeout = db_cfg.get("primary_timeout", 30)
        primary_models = [m.strip() for m in db_cfg["primary_model"].split(",") if m.strip()]
        if not primary_models:
            primary_models = [db_cfg["primary_model"]]
        for i, model in enumerate(primary_models):
            suffix = "-primary" if i == 0 else f"-alt{i}"
            chain.append(_Provider(
                name=provider_name + suffix,
                url=primary_url,
                key=primary_key,
                model=model,
                timeout=primary_timeout,
            ))
        for fb in db_cfg.get("fallback_providers", []):
            if fb.get("enabled") and fb.get("key") and "****" not in fb.get("key", ""):
                fb_models = [m.strip() for m in fb.get("model", "").split(",") if m.strip()]
                if not fb_models:
                    fb_models = [fb.get("model", "")]
                fb_name = fb.get("name", "fallback")
                for j, model in enumerate(fb_models):
                    suffix = "" if j == 0 else f"-alt{j}"
                    chain.append(_Provider(
                        name=fb_name + suffix,
                        url=_ensure_chat_url(fb.get("url", "")),
                        key=fb["key"],
                        model=model,
                        timeout=int(fb.get("timeout", 30)),
                    ))
    elif settings.ai_api_key:
        # Last-resort env fallback — single provider only, no hardcoded alts
        chain.append(_Provider(
            name="env-primary",
            url=_ensure_chat_url(settings.ai_api_url),
            key=settings.ai_api_key,
            model=settings.ai_model,
            timeout=settings.ai_timeout,
        ))

    _fallback_chain = chain
    _chain_built_ts = now
    names = [f"{p.name}({p.model})" for p in chain]
    logger.info("ai_chain_loaded", providers=names, source="db" if (db_cfg and db_cfg.get("primary_api_key")) else "env")
    return chain

# Re-exported for backward compat (used by ai_settings.py get_default_prompts)
_DEFAULT_SYSTEM_PROMPT = INTEL_SUMMARY_PROMPT


# ── Shared helper: call provider with fallback ────────────

async def _call_with_fallback(
    messages: list[dict],
    *,
    max_tokens: int = 800,
    temperature: float = 0.3,
    caller: str = "ai",
    model_override: str | None = None,
) -> str | None:
    """Try each provider in the fallback chain until one succeeds.

    Returns the response content string, or None if all providers fail.
    Specifically retries on HTTP 429 (rate-limit) and 503 (overloaded).
    """
    chain = await _get_chain_async()
    if not chain:
        logger.warning(f"{caller}_no_providers")
        return None

    for i, provider in enumerate(chain):
        try:
            async with httpx.AsyncClient(timeout=provider.timeout) as client:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {provider.key}",
                    "User-Agent": "IntelWatch/1.0",
                }
                payload = {
                    "model": model_override if (model_override and i == 0) else provider.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                logger.info(
                    f"{caller}_request",
                    provider=provider.name,
                    model=provider.model,
                    attempt=i + 1,
                    total=len(chain),
                )
                response = await client.post(provider.url, json=payload, headers=headers)

                # Rate-limit, overloaded, or forbidden → try next provider
                if response.status_code in (429, 503, 403):
                    body = response.text[:200]
                    logger.warning(
                        f"{caller}_rate_limited",
                        provider=provider.name,
                        status=response.status_code,
                        body=body,
                    )
                    continue

                response.raise_for_status()

                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "").strip()
                    if content:
                        logger.info(
                            f"{caller}_ok",
                            provider=provider.name,
                            model=provider.model,
                            chars=len(content),
                        )
                        await _increment_provider_usage(provider.name)
                        return content

                logger.warning(f"{caller}_empty_response", provider=provider.name)

        except httpx.TimeoutException:
            logger.warning(f"{caller}_timeout", provider=provider.name)
        except httpx.HTTPStatusError as e:
            body = e.response.text[:300] if e.response else ""
            logger.warning(
                f"{caller}_http_error",
                provider=provider.name,
                status=e.response.status_code,
                body=body,
            )
        except Exception as e:
            logger.warning(f"{caller}_error", provider=provider.name, error=str(e))

    logger.error(f"{caller}_all_providers_exhausted", tried=len(chain))
    return None


# ── Public API ────────────────────────────────────────────

async def generate_summary(
    title: str,
    description: str | None = None,
    severity: str = "unknown",
    source_name: str = "",
    cve_ids: list[str] | None = None,
    *,
    system_prompt: str | None = None,
    max_tokens: int = 300,
    cache_prefix: str = "ai_summary",
) -> str | None:
    """Generate an AI summary with automatic provider fallback.

    Tries each provider in the fallback chain on rate-limit (429).
    Returns None if AI is unavailable or all providers are exhausted.
    """
    # Check feature toggle and daily limit
    if not await is_feature_enabled("intel_summary"):
        logger.info("ai_intel_summary_disabled")
        return None
    if not await check_daily_limit("intel_summary"):
        logger.info("ai_intel_summary_daily_limit_reached")
        return None

    chain = await _get_chain_async()
    if not chain:
        logger.warning("ai_no_providers_configured")
        return None

    # Check cache first
    ttl = await get_cache_ttl("summary")
    ck = cache_key(cache_prefix, title, severity)
    cached = await get_cached(ck)
    if cached and isinstance(cached, dict):
        return cached.get("summary")

    # Use custom prompt if configured
    custom = await get_custom_prompt("intel_summary")
    final_prompt = system_prompt or custom or _DEFAULT_SYSTEM_PROMPT

    prompt = _build_prompt(title, description, severity, source_name, cve_ids or [])
    messages = [
        {"role": "system", "content": final_prompt},
        {"role": "user", "content": prompt},
    ]

    summary = await _call_with_fallback(
        messages, max_tokens=max_tokens, temperature=0.3, caller="ai_summary",
        model_override=await get_feature_model("intel_summary"),
    )

    if summary:
        await set_cached(ck, {"summary": summary}, ttl=ttl)
        await increment_daily_usage("intel_summary")

    return summary


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


async def chat_completion(
    system_prompt: str,
    user_prompt: str,
    *,
    max_tokens: int = 800,
    temperature: float = 0.3,
    feature: str | None = None,
) -> str | None:
    """Generic chat completion with automatic provider fallback.

    Tries each provider in the fallback chain on rate-limit (429).
    Returns content string or None if all providers are exhausted.
    """
    if feature:
        if not await is_feature_enabled(feature):
            logger.info("ai_feature_disabled", feature=feature)
            return None
        if not await check_daily_limit(feature):
            logger.info("ai_daily_limit_reached", feature=feature)
            return None

    chain = await _get_chain_async()
    if not chain:
        logger.warning("ai_chat_no_providers_configured")
        return None

    # Apply custom prompt override if configured for this feature
    effective_system = system_prompt
    if feature:
        custom = await get_custom_prompt(feature)
        if custom:
            effective_system = custom

    messages = [
        {"role": "system", "content": effective_system},
        {"role": "user", "content": user_prompt},
    ]

    result = await _call_with_fallback(
        messages, max_tokens=max_tokens, temperature=temperature, caller="ai_chat",
        model_override=await get_feature_model(feature) if feature else None,
    )

    if result and feature:
        await increment_daily_usage(feature)

    return result


def _strip_json_fences(text: str) -> str:
    """Remove markdown code fences from an AI response to extract raw JSON."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()
    if cleaned.startswith("json"):
        cleaned = cleaned[4:].strip()
    return cleaned


async def chat_completion_json(
    system_prompt: str,
    user_prompt: str,
    *,
    max_tokens: int = 800,
    temperature: float = 0.3,
    required_keys: list[str] | None = None,
    caller: str = "ai_json",
    feature: str | None = None,
) -> dict | None:
    """Chat completion that parses and validates JSON response.

    Strips markdown fences, parses JSON, validates required keys are present.
    On parse failure, retries once with a corrective prompt asking the LLM
    to fix its output. Returns parsed dict or None.
    """
    raw = await chat_completion(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        feature=feature,
    )

    if not raw:
        return None

    # First attempt to parse
    cleaned = _strip_json_fences(raw)
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"{caller}_json_parse_error", error=str(e), raw=raw[:200])

        # Corrective retry — ask the LLM to fix its own output
        retry_raw = await chat_completion(
            system_prompt=JSON_REPAIR_PROMPT,
            user_prompt=f"Fix this JSON:\n{raw[:4000]}",
            max_tokens=max_tokens,
            temperature=0.1,
        )
        if not retry_raw:
            logger.warning(f"{caller}_json_retry_failed")
            return None

        cleaned_retry = _strip_json_fences(retry_raw)
        try:
            data = json.loads(cleaned_retry)
        except (json.JSONDecodeError, ValueError) as e2:
            logger.warning(f"{caller}_json_retry_parse_error", error=str(e2))
            return None

    # Validate required keys
    if required_keys:
        missing = [k for k in required_keys if k not in data]
        if missing:
            logger.warning(f"{caller}_missing_required_keys", missing=missing)
            # Still return what we got — partial enrichment is better than nothing

    return data


async def check_ai_health() -> dict:
    """Check health of all configured AI providers.

    Returns dict with overall status and per-provider details.
    """
    chain = await _get_chain_async()
    if not chain:
        return {"healthy": False, "providers": [], "reason": "no_providers"}

    results = []
    any_healthy = False

    for provider in chain:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                headers = {
                    "Authorization": f"Bearer {provider.key}",
                    "User-Agent": "IntelWatch/1.0",
                }
                # Strip /chat/completions to get the API base URL
                base = provider.url.rstrip("/")
                for suffix in ("/chat/completions", "/chat"):
                    if base.endswith(suffix):
                        base = base[: -len(suffix)]
                        break
                response = await client.get(f"{base}/models", headers=headers)
                ok = response.status_code == 200
                usage = await _get_provider_usage(provider.name)
                results.append({"name": provider.name, "model": provider.model, "healthy": ok, "today_requests": usage})
                if ok:
                    any_healthy = True
        except Exception:
            usage = await _get_provider_usage(provider.name)
            results.append({"name": provider.name, "model": provider.model, "healthy": False, "today_requests": usage})

    return {"healthy": any_healthy, "providers": results}
