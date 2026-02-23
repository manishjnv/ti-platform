"""AbuseIPDB feed connector (free tier: 1000 checks/day)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseIPDBConnector(BaseFeedConnector):
    FEED_NAME = "abuseipdb"
    SOURCE_RELIABILITY = 80

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        if not settings.abuseipdb_api_key:
            logger.warning("abuseipdb_no_api_key")
            return []

        headers = {
            "Key": settings.abuseipdb_api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": 90,
            "limit": 500,
        }

        response = await self.client.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        items = data.get("data", [])
        logger.info("abuseipdb_fetch", total=len(items))
        return items

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            ip = raw.get("ipAddress", "")
            if not ip:
                continue

            abuse_score = raw.get("abuseConfidenceScore", 0)
            country = raw.get("countryCode", "")
            last_reported = raw.get("lastReportedAt", "")

            # Map abuse score to severity
            if abuse_score >= 90:
                severity = "critical"
            elif abuse_score >= 70:
                severity = "high"
            elif abuse_score >= 50:
                severity = "medium"
            else:
                severity = "low"

            published_at = None
            if last_reported:
                try:
                    published_at = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            geo = [country] if country else []

            items.append({
                "id": uuid.uuid4(),
                "title": f"[AbuseIPDB] Malicious IP: {ip}",
                "summary": f"Abuse score: {abuse_score}% | Country: {country or 'Unknown'}",
                "description": f"IP address {ip} reported to AbuseIPDB with {abuse_score}% confidence.",
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,
                "confidence": min(abuse_score, 100),
                "source_name": "AbuseIPDB",
                "source_url": f"https://www.abuseipdb.com/check/{ip}",
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": ip,
                "feed_type": "ioc",
                "asset_type": "ip",
                "tlp": "TLP:CLEAR",
                "tags": ["malicious_ip", severity],
                "geo": geo,
                "industries": [],
                "cve_ids": [],
                "affected_products": [],
                "related_ioc_count": 1,
                "is_kev": False,
                "exploit_available": False,
                "exploitability_score": None,
                "source_hash": self.generate_hash("abuseipdb", ip),
            })

        return items
