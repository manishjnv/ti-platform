"""AI Settings API — admin-only platform-wide AI configuration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import get_settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.core.redis import redis_client
from app.middleware.auth import require_admin
from app.models.models import AISetting, User

logger = get_logger(__name__)
env_settings = get_settings()

router = APIRouter(prefix="/ai-settings", tags=["ai-settings"])

# Redis key for daily usage counters
_DAILY_KEY_PREFIX = "ai_daily_usage"

# Fields that can be updated
_UPDATABLE_FIELDS = {
    "ai_enabled", "primary_provider", "primary_api_url", "primary_api_key",
    "primary_model", "primary_timeout", "fallback_providers",
    "feature_intel_summary", "feature_intel_enrichment", "feature_news_enrichment",
    "feature_live_lookup", "feature_report_gen", "feature_briefing_gen",
    "daily_limit_intel_summary", "daily_limit_intel_enrichment",
    "daily_limit_news_enrichment", "daily_limit_live_lookup",
    "daily_limit_report_gen", "daily_limit_briefing_gen",
    "prompt_intel_summary", "prompt_intel_enrichment", "prompt_news_enrichment",
    "prompt_live_lookup", "prompt_report_gen", "prompt_briefing_gen",
    "default_temperature", "default_max_tokens",
    "requests_per_minute", "batch_delay_ms",
    "cache_ttl_summary", "cache_ttl_enrichment", "cache_ttl_lookup",
    "model_intel_summary", "model_intel_enrichment", "model_news_enrichment",
    "model_live_lookup", "model_report_gen", "model_briefing_gen",
}

# Optimal defaults — hardcoded in backend code (secure, not user-editable).
# Used by the reset-to-defaults endpoint to prevent misconfiguration.
AI_OPTIMAL_DEFAULTS: dict = {
    "ai_enabled": True,
    "primary_provider": "groq",
    "primary_api_url": "https://api.groq.com/openai/v1/chat/completions",
    "primary_model": "llama-3.3-70b-versatile",
    "primary_timeout": 30,
    "feature_intel_summary": True,
    "feature_intel_enrichment": True,
    "feature_news_enrichment": True,
    "feature_live_lookup": True,
    "feature_report_gen": True,
    "feature_briefing_gen": True,
    "daily_limit_intel_summary": 500,
    "daily_limit_intel_enrichment": 200,
    "daily_limit_news_enrichment": 300,
    "daily_limit_live_lookup": 100,
    "daily_limit_report_gen": 50,
    "daily_limit_briefing_gen": 20,
    "default_temperature": 0.3,
    "default_max_tokens": 800,
    "requests_per_minute": 30,
    "batch_delay_ms": 1000,
    "cache_ttl_summary": 3600,
    "cache_ttl_enrichment": 21600,
    "cache_ttl_lookup": 300,
    "model_intel_summary": "",
    "model_intel_enrichment": "",
    "model_news_enrichment": "",
    "model_live_lookup": "",
    "model_report_gen": "",
    "model_briefing_gen": "",
    "prompt_intel_summary": "",
    "prompt_intel_enrichment": "",
    "prompt_news_enrichment": "",
    "prompt_live_lookup": "",
    "prompt_report_gen": "",
    "prompt_briefing_gen": "",
}


async def _get_or_create_settings(db: AsyncSession) -> AISetting:
    """Get the singleton AI settings row, creating it if absent."""
    result = await db.execute(select(AISetting).where(AISetting.key == "default"))
    row = result.scalar_one_or_none()
    if not row:
        row = AISetting(key="default")
        # Seed from env vars so first load reflects current config
        row.ai_enabled = env_settings.ai_enabled
        row.primary_api_url = env_settings.ai_api_url
        row.primary_api_key = env_settings.ai_api_key
        row.primary_model = env_settings.ai_model
        row.primary_timeout = env_settings.ai_timeout

        # Seed fallback providers from env
        fallbacks = []
        if env_settings.cerebras_api_key:
            fallbacks.append({
                "name": "cerebras", "url": "https://api.cerebras.ai/v1/chat/completions",
                "key": env_settings.cerebras_api_key, "model": "llama3.1-8b",
                "timeout": 60, "enabled": True,
            })
        if env_settings.hf_api_key:
            fallbacks.append({
                "name": "huggingface", "url": "https://api-inference.huggingface.co/v1/chat/completions",
                "key": env_settings.hf_api_key, "model": "mistralai/Mistral-7B-Instruct-v0.3",
                "timeout": 60, "enabled": True,
            })
        row.fallback_providers = fallbacks
        db.add(row)
        await db.flush()
    return row


def _serialize(row: AISetting) -> dict:
    """Serialize AISetting to JSON-safe dict, masking API keys."""
    return {
        "ai_enabled": row.ai_enabled,
        "primary_provider": row.primary_provider,
        "primary_api_url": row.primary_api_url,
        "primary_api_key": _mask(row.primary_api_key),
        "primary_api_key_set": bool(row.primary_api_key),
        "primary_model": row.primary_model,
        "primary_timeout": row.primary_timeout,
        "fallback_providers": [
            {**p, "key": _mask(p.get("key", "")), "key_set": bool(p.get("key")), "key_masked": _mask(p.get("key", ""))}
            for p in (row.fallback_providers or [])
        ],
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
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _mask(key: str) -> str:
    if not key or len(key) < 8:
        return "***" if key else ""
    return key[:4] + "****" + key[-4:]


@router.get("")
async def get_ai_settings(
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get current AI configuration (admin only)."""
    row = await _get_or_create_settings(db)
    await db.commit()
    data = _serialize(row)
    # Attach daily usage counters
    data["daily_usage"] = await _get_daily_usage()
    return data


@router.put("")
async def update_ai_settings(
    body: dict,
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update AI configuration (admin only). Partial update — only send changed fields."""
    row = await _get_or_create_settings(db)

    for field, value in body.items():
        if field not in _UPDATABLE_FIELDS:
            continue

        # Validate types
        if field.startswith("feature_") and not isinstance(value, bool):
            continue
        if field.startswith("daily_limit_") and not isinstance(value, int):
            continue
        if field.startswith("cache_ttl_") and not isinstance(value, int):
            continue
        if field in ("default_temperature",) and not isinstance(value, (int, float)):
            continue
        if field in ("default_max_tokens", "requests_per_minute", "batch_delay_ms", "primary_timeout") and not isinstance(value, int):
            continue

        # Special handling for fallback_providers
        if field == "fallback_providers":
            if not isinstance(value, list):
                continue
            # Preserve existing keys if new entry sends empty key
            existing = {p.get("name"): p for p in (row.fallback_providers or [])}
            merged = []
            for p in value:
                if not isinstance(p, dict) or not p.get("name"):
                    continue
                # Preserve existing key if new entry sends empty or masked key
                new_key = p.get("key", "")
                if not new_key or "****" in new_key:
                    # Always fall back to existing real key; never store masked values
                    new_key = existing.get(p["name"], {}).get("key", "")
                merged.append({
                    "name": p.get("name", ""),
                    "url": p.get("url", ""),
                    "key": new_key,
                    "model": p.get("model", ""),
                    "timeout": int(p.get("timeout", 30)),
                    "enabled": bool(p.get("enabled", True)),
                })
            value = merged

        # Special handling for api key — don't overwrite with empty or masked value
        if field == "primary_api_key" and (not value or "****" in str(value)):
            continue

        setattr(row, field, value)

    row.updated_by = user.id
    row.updated_at = datetime.now(timezone.utc)

    if row.fallback_providers is not None:
        flag_modified(row, "fallback_providers")

    await db.commit()

    # Invalidate the cached settings in ai.py
    await _invalidate_ai_cache()

    data = _serialize(row)
    data["daily_usage"] = await _get_daily_usage()
    logger.info("ai_settings_updated", user=user.email)
    return data


@router.post("/test-provider")
async def test_ai_provider(
    body: dict,
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Test an AI provider connection with a simple prompt."""
    import httpx

    url = body.get("url", "")
    key = body.get("key", "")
    model = body.get("model", "")
    timeout = int(body.get("timeout", 15))
    # Which provider to test: "primary" or fallback index (0, 1, ...)
    provider_type = body.get("provider_type", None)

    # Always resolve API keys from database when provider_type is specified
    # (frontend sends masked keys after save/reload)
    if provider_type is not None:
        row = await _get_or_create_settings(db)
        if str(provider_type) == "primary":
            key = row.primary_api_key or key
            if not url:
                url = row.primary_api_url or ""
            if not model:
                model = row.primary_model or ""
        else:
            try:
                idx = int(provider_type)
                fb = (row.fallback_providers or [])[idx]
                key = fb.get("key", "") or key
                if not url:
                    url = fb.get("url", "")
                if not model:
                    model = fb.get("model", "")
            except (ValueError, IndexError):
                pass
    elif key and "****" in key:
        # Fallback: old frontend without provider_type sent a masked key.
        # Try to match by URL to find the real key from the database.
        row = await _get_or_create_settings(db)
        primary_url = (row.primary_api_url or "").rstrip("/").replace("/chat/completions", "")
        test_url_base = url.rstrip("/").replace("/chat/completions", "")
        if primary_url and test_url_base and primary_url == test_url_base:
            key = row.primary_api_key or key
        else:
            for fb in (row.fallback_providers or []):
                fb_url_base = fb.get("url", "").rstrip("/").replace("/chat/completions", "")
                if fb_url_base and test_url_base and fb_url_base == test_url_base:
                    key = fb.get("key", "") or key
                    break

    logger.info("test_provider_request",
                provider_type=provider_type,
                url=url,
                model=model,
                key_len=len(key) if key else 0,
                key_masked="****" in key if key else False)

    if not url or not key or not model:
        raise HTTPException(400, "url, key, and model are required")

    # Ensure we hit the chat completions endpoint
    test_url = url.rstrip("/")
    # Gemini requires /openai/ in the path for OpenAI-compatible mode
    if "generativelanguage.googleapis.com" in test_url and "/openai" not in test_url:
        test_url = test_url.rstrip("/") + "/openai"
    if not test_url.endswith("/chat/completions"):
        test_url += "/chat/completions"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                test_url,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "Respond with exactly: OK"},
                        {"role": "user", "content": "Test"},
                    ],
                    "max_tokens": 10,
                    "temperature": 0,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                logger.info("test_provider_success", provider_type=provider_type, model=model)
                return {"success": True, "status": resp.status_code, "response": content.strip()[:100]}
            logger.warning("test_provider_fail", provider_type=provider_type, status=resp.status_code, error=resp.text[:200])
            return {"success": False, "status": resp.status_code, "error": resp.text[:200]}
    except httpx.TimeoutException:
        return {"success": False, "status": 0, "error": "Connection timed out"}
    except Exception as e:
        return {"success": False, "status": 0, "error": str(e)[:200]}


@router.get("/usage")
async def get_ai_usage(
    user: Annotated[User, Depends(require_admin)],
):
    """Get today's AI usage counters per feature."""
    return await _get_daily_usage()


@router.post("/reset-usage")
async def reset_ai_usage(
    user: Annotated[User, Depends(require_admin)],
):
    """Reset today's usage counters."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    features = [
        "intel_summary", "intel_enrichment", "news_enrichment",
        "live_lookup", "report_gen", "briefing_gen",
    ]
    r = redis_client
    for f in features:
        await r.delete(f"{_DAILY_KEY_PREFIX}:{f}:{today}")
    return {"reset": True}


@router.get("/defaults")
async def get_ai_defaults(
    user: Annotated[User, Depends(require_admin)],
):
    """Return the optimal default settings (read-only, hardcoded in backend)."""
    return AI_OPTIMAL_DEFAULTS


@router.get("/default-prompts")
async def get_default_prompts(
    user: Annotated[User, Depends(require_admin)],
):
    """Return the built-in system prompts for each AI feature (read-only reference)."""
    from app.services.ai import _DEFAULT_SYSTEM_PROMPT
    from app.routes.intel import _ENRICHMENT_SYSTEM_PROMPT
    from app.services.news import _NEWS_ENRICHMENT_SYSTEM

    # Report generation prompt (inline in reports.py)
    report_gen_prompt = (
        "You are a cybersecurity threat intelligence analyst writing an executive summary "
        "for a formal threat intelligence report. Based on the report title, sections, and "
        "linked intelligence items provided, write a concise executive summary (3-5 sentences). "
        "Cover: what the threat is, who/what is affected, the severity and urgency, and "
        "recommended actions. Use professional, direct language suitable for C-level briefings."
    )

    briefing_gen_prompt = (
        "You are a senior threat intelligence analyst. Generate comprehensive, actionable "
        "threat briefings in JSON format. Keep the JSON valid."
    )

    live_lookup_prompt = (
        "You are an expert threat intelligence analyst. Analyze the given IOC lookup results and produce "
        "a structured JSON analysis. Respond ONLY with valid JSON, no markdown, no code blocks.\n\n"
        "Required JSON structure:\n"
        '{\n'
        '  "summary": "2-4 sentence executive summary of what this IOC is and its risk level",\n'
        '  "threat_actors": ["list of threat actors/groups associated, empty if none known"],\n'
        '  "timeline": [{"date": "YYYY-MM-DD or description", "event": "what happened"}],\n'
        '  "affected_products": ["vendor:product pairs or product names impacted"],\n'
        '  "fix_remediation": "Specific recommended fix or remediation steps. Null if not applicable",\n'
        '  "known_breaches": "Description of any known breaches or campaigns. Null if none",\n'
        '  "key_findings": ["3-6 bullet point key findings, each a concise sentence"]\n'
        '}\n\n'
        "Rules: Be factual. Do not fabricate data. If information is not available, use empty arrays or null. "
        "Keep it concise and actionable. Focus on what a SOC analyst needs to know."
    )

    return {
        "intel_summary": _DEFAULT_SYSTEM_PROMPT,
        "intel_enrichment": _ENRICHMENT_SYSTEM_PROMPT,
        "news_enrichment": _NEWS_ENRICHMENT_SYSTEM,
        "live_lookup": live_lookup_prompt,
        "report_gen": report_gen_prompt,
        "briefing_gen": briefing_gen_prompt,
    }


@router.post("/reset-defaults")
async def reset_ai_defaults(
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Reset AI settings to optimal defaults. Preserves API keys and fallback providers."""
    row = await _get_or_create_settings(db)

    for field, value in AI_OPTIMAL_DEFAULTS.items():
        if field not in _UPDATABLE_FIELDS:
            continue
        # Never reset secrets
        if field in ("primary_api_key", "fallback_providers"):
            continue
        setattr(row, field, value)

    # Clear custom prompts
    for f in ("intel_summary", "intel_enrichment", "news_enrichment",
              "live_lookup", "report_gen", "briefing_gen"):
        setattr(row, f"prompt_{f}", None)

    row.updated_by = user.id
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await _invalidate_ai_cache()

    data = _serialize(row)
    data["daily_usage"] = await _get_daily_usage()
    logger.info("ai_settings_reset_to_defaults", user=user.email)
    return data


@router.get("/health")
async def ai_provider_health(
    user: Annotated[User, Depends(require_admin)],
):
    """Check health of all configured AI providers."""
    from app.services.ai import check_ai_health
    return await check_ai_health()


@router.post("/promote-fallback")
async def promote_fallback(
    body: dict,
    user: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Swap a fallback provider to primary (server-side, handles real keys)."""
    idx = body.get("index")
    if idx is None or not isinstance(idx, int):
        raise HTTPException(400, "index is required (integer)")

    row = await _get_or_create_settings(db)
    fallbacks = row.fallback_providers or []
    if idx < 0 or idx >= len(fallbacks):
        raise HTTPException(400, f"Invalid fallback index: {idx}")

    fb = fallbacks[idx]

    # Save current primary as fallback entry
    old_primary = {
        "name": row.primary_provider,
        "url": row.primary_api_url,
        "key": row.primary_api_key,
        "model": row.primary_model,
        "timeout": row.primary_timeout,
        "enabled": True,
    }

    # Promote fallback to primary
    row.primary_provider = fb.get("name", "")
    row.primary_api_url = fb.get("url", "")
    row.primary_api_key = fb.get("key", "")
    row.primary_model = fb.get("model", "")
    row.primary_timeout = int(fb.get("timeout", 30))

    # Replace the promoted fallback with old primary
    fallbacks[idx] = old_primary
    row.fallback_providers = fallbacks
    flag_modified(row, "fallback_providers")

    row.updated_by = user.id
    row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await _invalidate_ai_cache()

    data = _serialize(row)
    data["daily_usage"] = await _get_daily_usage()
    logger.info("ai_fallback_promoted", index=idx, new_primary=row.primary_provider, user=user.email)
    return data


# ─── Helpers ─────────────────────────────────────────────

async def _get_daily_usage() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    features = [
        "intel_summary", "intel_enrichment", "news_enrichment",
        "live_lookup", "report_gen", "briefing_gen",
    ]
    r = redis_client
    usage = {}
    for f in features:
        val = await r.get(f"{_DAILY_KEY_PREFIX}:{f}:{today}")
        usage[f] = int(val) if val else 0
    return usage


async def _invalidate_ai_cache():
    """Clear the cached AI settings so ai.py reloads from DB on next call."""
    r = redis_client
    await r.delete("ai_settings_cache")
