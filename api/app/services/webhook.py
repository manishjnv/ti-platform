"""Webhook notifier — delivers notifications to external webhook URLs.

Supports both sync (worker) and async (API) contexts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.logging import get_logger

logger = get_logger(__name__)

WEBHOOK_TIMEOUT = 10


def _build_payload(notification: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": "notification",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "title": notification.get("title", ""),
            "message": notification.get("message", ""),
            "severity": notification.get("severity", "info"),
            "category": notification.get("category", "system"),
            "entity_type": notification.get("entity_type"),
            "entity_id": notification.get("entity_id"),
            "metadata": notification.get("metadata", {}),
        },
    }


def _build_headers(payload: dict, secret: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "IntelWatch/1.0",
    }
    if secret:
        body = json.dumps(payload, sort_keys=True)
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-IntelWatch-Signature"] = sig
    return headers


# ─── Sync delivery (used by worker rule evaluation) ──────


def deliver_webhook_sync(
    url: str,
    notification: dict[str, Any],
    *,
    secret: str | None = None,
) -> dict[str, Any]:
    """POST notification payload to a webhook URL (synchronous)."""
    payload = _build_payload(notification)
    headers = _build_headers(payload, secret)

    try:
        with httpx.Client(timeout=WEBHOOK_TIMEOUT) as client:
            resp = client.post(url, json=payload, headers=headers)

        return {
            "success": 200 <= resp.status_code < 300,
            "status_code": resp.status_code,
            "response": resp.text[:500] if resp.text else "",
        }
    except httpx.TimeoutException:
        logger.warning("webhook_timeout", url=url)
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        logger.error("webhook_error", url=url, error=str(e))
        return {"success": False, "error": str(e)}


# ─── Async delivery (used by API test endpoint) ──────────


async def deliver_webhook_async(
    url: str,
    notification: dict[str, Any],
    *,
    secret: str | None = None,
) -> dict[str, Any]:
    """POST notification payload to a webhook URL (async)."""
    payload = _build_payload(notification)
    headers = _build_headers(payload, secret)

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            resp = await client.post(url, json=payload, headers=headers)

        return {
            "success": 200 <= resp.status_code < 300,
            "status_code": resp.status_code,
            "response": resp.text[:500] if resp.text else "",
        }
    except httpx.TimeoutException:
        logger.warning("webhook_timeout", url=url)
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        logger.error("webhook_error", url=url, error=str(e))
        return {"success": False, "error": str(e)}


# ─── Channel dispatcher ──────────────────────────────────


def deliver_to_channels_sync(
    channels: list[str],
    notification_data: dict[str, Any],
    rule_conditions: dict[str, Any] | None = None,
) -> list[dict]:
    """Deliver notification to external channels (sync, for worker).

    Currently supports:
    - webhook / slack: POSTs to rule-configured URL
    """
    results = []
    webhook_url = (rule_conditions or {}).get("webhook_url")
    webhook_secret = (rule_conditions or {}).get("webhook_secret")

    for channel in channels:
        if channel == "in_app":
            continue
        if channel in ("webhook", "slack") and webhook_url:
            result = deliver_webhook_sync(
                webhook_url, notification_data, secret=webhook_secret
            )
            result["channel"] = channel
            results.append(result)
            logger.info(
                "webhook_delivered",
                channel=channel,
                success=result.get("success"),
                url=webhook_url[:60],
            )

    return results
