"""AI summarization service — uses OpenAI-compatible API with multi-provider fallback.

Supports: Groq, Cerebras, Google Gemini, OpenAI, Open-WebUI, etc.

Features:
  - Async HTTP calls with automatic fallback on rate-limit (429)
  - Multi-provider chain: Groq → Cerebras → Groq alt models
  - Redis caching for summaries
  - Timeout fallback
  - Custom system prompts per use-case
  - Graceful "AI unavailable" state
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import cache_key, get_cached, set_cached

logger = get_logger(__name__)
settings = get_settings()


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


def _build_fallback_chain() -> list[_Provider]:
    """Build ordered list of providers.  Primary from env, then free fallbacks."""
    chain: list[_Provider] = []

    # 1. Primary — from env (Groq llama-3.3-70b-versatile)
    if settings.ai_api_key:
        chain.append(_Provider(
            name="groq-primary",
            url=settings.ai_api_url,
            key=settings.ai_api_key,
            model=settings.ai_model,
            timeout=settings.ai_timeout,
        ))

    # 2. Groq alt model — same key, different model (separate per-model bucket)
    if settings.ai_api_key:
        chain.append(_Provider(
            name="groq-llama3.1-8b",
            url="https://api.groq.com/openai/v1/chat/completions",
            key=settings.ai_api_key,
            model="llama-3.1-8b-instant",
            timeout=30,
        ))

    # 3. Cerebras — free tier, fast inference, Qwen3 235B
    cerebras_key = getattr(settings, "cerebras_api_key", "")
    if cerebras_key:
        chain.append(_Provider(
            name="cerebras",
            url="https://api.cerebras.ai/v1/chat/completions",
            key=cerebras_key,
            model="qwen-3-235b-a22b-instruct-2507",
            timeout=60,
        ))

    # 4. Groq Qwen3 32B — another model bucket
    if settings.ai_api_key:
        chain.append(_Provider(
            name="groq-qwen3",
            url="https://api.groq.com/openai/v1/chat/completions",
            key=settings.ai_api_key,
            model="qwen/qwen3-32b",
            timeout=30,
        ))

    # 5. HuggingFace Inference API (router) — free, good for structured tasks
    hf_key = getattr(settings, "hf_api_key", "")
    if hf_key:
        chain.append(_Provider(
            name="huggingface",
            url="https://router.huggingface.co/hf-inference/v1/chat/completions",
            key=hf_key,
            model="mistralai/Mistral-7B-Instruct-v0.3",
            timeout=60,
        ))

    return chain


_fallback_chain: list[_Provider] | None = None


def _get_chain() -> list[_Provider]:
    global _fallback_chain
    if _fallback_chain is None:
        _fallback_chain = _build_fallback_chain()
        names = [f"{p.name}({p.model})" for p in _fallback_chain]
        logger.info("ai_fallback_chain_built", providers=names, count=len(names))
    return _fallback_chain

_DEFAULT_SYSTEM_PROMPT = (
    "You are a cybersecurity threat intelligence analyst. "
    "Provide a concise 2-3 sentence summary of the following "
    "threat intelligence item. Focus on impact, affected systems, "
    "and recommended actions. Be direct and technical."
)


# ── Shared helper: call provider with fallback ────────────

async def _call_with_fallback(
    messages: list[dict],
    *,
    max_tokens: int = 800,
    temperature: float = 0.3,
    caller: str = "ai",
) -> str | None:
    """Try each provider in the fallback chain until one succeeds.

    Returns the response content string, or None if all providers fail.
    Specifically retries on HTTP 429 (rate-limit) and 503 (overloaded).
    """
    chain = _get_chain()
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
                    "model": provider.model,
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

                # Rate-limit or overloaded → try next provider
                if response.status_code in (429, 503):
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
    if not settings.ai_enabled:
        logger.info("ai_disabled")
        return None

    chain = _get_chain()
    if not chain:
        logger.warning("ai_no_providers_configured")
        return None

    # Check cache first
    ck = cache_key(cache_prefix, title, severity)
    cached = await get_cached(ck)
    if cached:
        return cached.get("summary")

    prompt = _build_prompt(title, description, severity, source_name, cve_ids or [])
    messages = [
        {"role": "system", "content": system_prompt or _DEFAULT_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    summary = await _call_with_fallback(
        messages, max_tokens=max_tokens, temperature=0.3, caller="ai_summary"
    )

    if summary:
        await set_cached(ck, {"summary": summary}, ttl=settings.cache_ttl_ai_summary)

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
) -> str | None:
    """Generic chat completion with automatic provider fallback.

    Tries each provider in the fallback chain on rate-limit (429).
    Returns content string or None if all providers are exhausted.
    """
    if not settings.ai_enabled:
        logger.info("ai_disabled")
        return None

    chain = _get_chain()
    if not chain:
        logger.warning("ai_chat_no_providers_configured")
        return None

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    return await _call_with_fallback(
        messages, max_tokens=max_tokens, temperature=temperature, caller="ai_chat"
    )


async def check_ai_health() -> dict:
    """Check health of all configured AI providers.

    Returns dict with overall status and per-provider details.
    """
    chain = _get_chain()
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
                base = provider.url.rsplit("/", 1)[0]
                response = await client.get(f"{base}/models", headers=headers)
                ok = response.status_code == 200
                results.append({"name": provider.name, "model": provider.model, "healthy": ok})
                if ok:
                    any_healthy = True
        except Exception:
            results.append({"name": provider.name, "model": provider.model, "healthy": False})

    return {"healthy": any_healthy, "providers": results}
