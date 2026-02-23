"""Dynamic risk scoring service (v1).

Score 0-100 based on configurable weights:
  - KEV presence (0 or max)
  - Severity mapping
  - Source reliability
  - Freshness (time decay)
  - IOC prevalence
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.core.logging import get_logger

logger = get_logger(__name__)

DEFAULT_WEIGHTS = {
    "kev_presence": 25,
    "severity": 25,
    "source_reliability": 15,
    "freshness": 20,
    "ioc_prevalence": 15,
}

SEVERITY_SCORES = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 25,
    "info": 10,
    "unknown": 0,
}


def compute_risk_score(
    item: dict,
    weights: dict | None = None,
) -> int:
    """Compute risk score for a single intel item."""
    w = weights or DEFAULT_WEIGHTS
    total_weight = sum(w.values())
    if total_weight == 0:
        return 0

    score = 0.0

    # 1. KEV presence (binary)
    if item.get("is_kev", False):
        score += w.get("kev_presence", 25) * 1.0
    else:
        score += 0

    # 2. Severity
    sev = item.get("severity", "unknown")
    sev_score = SEVERITY_SCORES.get(sev, 0) / 100.0
    score += w.get("severity", 25) * sev_score

    # 3. Source reliability
    reliability = item.get("source_reliability", 50) / 100.0
    score += w.get("source_reliability", 15) * reliability

    # 4. Freshness (decay over 90 days)
    freshness = _compute_freshness(item.get("published_at"))
    score += w.get("freshness", 20) * freshness

    # 5. IOC prevalence
    ioc_count = item.get("related_ioc_count", 0)
    ioc_factor = min(ioc_count / 50.0, 1.0)  # Cap at 50 IOCs
    score += w.get("ioc_prevalence", 15) * ioc_factor

    # Normalize to 0-100
    final = (score / total_weight) * 100.0

    # Boost for exploit availability
    if item.get("exploit_available", False):
        final = min(final + 10, 100)

    # CVSS boost
    cvss = item.get("exploitability_score")
    if cvss and cvss >= 9.0:
        final = min(final + 5, 100)

    return max(0, min(100, round(final)))


def _compute_freshness(published_at: datetime | str | None) -> float:
    """Return freshness factor 0.0 - 1.0. Newer = higher."""
    if not published_at:
        return 0.3  # Unknown date gets moderate score

    if isinstance(published_at, str):
        try:
            published_at = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return 0.3

    now = datetime.now(timezone.utc)
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=timezone.utc)

    age_days = (now - published_at).total_seconds() / 86400.0
    if age_days <= 1:
        return 1.0
    elif age_days <= 7:
        return 0.9
    elif age_days <= 30:
        return 0.7
    elif age_days <= 90:
        return 0.4
    else:
        return 0.1


def batch_score(items: list[dict], weights: dict | None = None) -> list[dict]:
    """Score a batch of items and return them with updated risk_score."""
    for item in items:
        item["risk_score"] = compute_risk_score(item, weights)
    return items
