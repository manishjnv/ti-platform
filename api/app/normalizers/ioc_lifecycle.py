"""IOC lifecycle management — confidence decay and staleness scoring.

Provides time-based confidence decay per IOC type, TTL thresholds,
and staleness scoring to age out stale indicators automatically.
"""

from __future__ import annotations

from datetime import datetime, timezone

# ── TTL in days per IOC type (how long before an IOC is considered stale) ──
IOC_TTL_DAYS: dict[str, int] = {
    "ip": 30,          # IPs rotate fast (cloud, VPN, residential proxies)
    "domain": 90,      # Domains stay malicious longer
    "url": 14,         # URLs are the most ephemeral
    "hash_md5": 365,   # File hashes don't change
    "hash_sha1": 365,
    "hash_sha256": 365,
    "email": 180,      # Attacker emails are semi-persistent
    "cve": 730,        # CVEs remain relevant for years
}

DEFAULT_TTL_DAYS = 90

# ── Confidence decay tiers (age_days → multiplier) ──
# Applied as: effective_confidence = base_confidence * multiplier
_DECAY_TIERS: list[tuple[float, float]] = [
    (1.0, 1.0),     # ≤ 1 day: no decay
    (7.0, 0.95),    # ≤ 7 days: 5% decay
    (30.0, 0.80),   # ≤ 30 days: 20% decay
    (90.0, 0.50),   # ≤ 90 days: 50% decay
    (180.0, 0.25),  # ≤ 180 days: 75% decay
    (365.0, 0.10),  # ≤ 1 year: 90% decay
]


def ioc_age_days(last_seen: datetime | str | None) -> float:
    """Return the age of an IOC in fractional days from its last sighting."""
    if not last_seen:
        return 999.0  # Unknown age → treat as very stale

    if isinstance(last_seen, str):
        try:
            last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return 999.0

    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return max(0.0, (now - last_seen).total_seconds() / 86400.0)


def confidence_decay(
    base_score: int,
    last_seen: datetime | str | None,
    ioc_type: str | None = None,
) -> int:
    """Apply time-based confidence decay to a base score (0-100).

    Uses the IOC type's TTL to scale the decay — shorter-lived IOC types
    decay faster. Returns decayed score clamped to 0-100.
    """
    age = ioc_age_days(last_seen)

    # Scale age relative to the IOC type's TTL for proportional decay
    ttl = IOC_TTL_DAYS.get(ioc_type or "", DEFAULT_TTL_DAYS)
    scale_factor = DEFAULT_TTL_DAYS / ttl  # ip (30d) → 3x faster decay
    effective_age = age * scale_factor

    multiplier = 0.05  # Beyond all tiers → near zero
    for max_days, mult in _DECAY_TIERS:
        if effective_age <= max_days:
            multiplier = mult
            break

    return max(0, min(100, round(base_score * multiplier)))


def is_stale(
    last_seen: datetime | str | None,
    ioc_type: str | None = None,
) -> bool:
    """Check if an IOC has exceeded its type-specific TTL."""
    ttl = IOC_TTL_DAYS.get(ioc_type or "", DEFAULT_TTL_DAYS)
    return ioc_age_days(last_seen) > ttl


def staleness_score(
    last_seen: datetime | str | None,
    ioc_type: str | None = None,
) -> float:
    """Return a 0.0-1.0 staleness score (1.0 = fully stale / expired).

    Linearly interpolated within the IOC type's TTL window.
    """
    ttl = IOC_TTL_DAYS.get(ioc_type or "", DEFAULT_TTL_DAYS)
    age = ioc_age_days(last_seen)
    return min(1.0, age / ttl)


def sighting_boost(sighting_count: int) -> int:
    """Return a confidence bonus (0-20) based on repeated sightings.

    More corroboration → higher confidence, with diminishing returns.
    """
    if sighting_count <= 1:
        return 0
    if sighting_count <= 3:
        return 5
    if sighting_count <= 10:
        return 10
    if sighting_count <= 25:
        return 15
    return 20
