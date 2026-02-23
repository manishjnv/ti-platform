"""OTX (Open Threat Exchange) feed connector for context enrichment."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


class OTXConnector(BaseFeedConnector):
    FEED_NAME = "otx"
    SOURCE_RELIABILITY = 70

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        if not settings.otx_api_key:
            logger.warning("otx_no_api_key")
            return []

        headers = {"X-OTX-API-KEY": settings.otx_api_key}

        # Fetch recent pulses (subscribed)
        url = f"{OTX_BASE_URL}/pulses/subscribed"
        params: dict = {"limit": 50, "page": 1}
        if last_cursor:
            params["modified_since"] = last_cursor

        response = await self.client.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        pulses = data.get("results", [])
        logger.info("otx_fetch", total=len(pulses))
        return pulses

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for pulse in raw_items:
            pulse_id = pulse.get("id", "")
            name = pulse.get("name", "")
            description = pulse.get("description", "")
            tags = pulse.get("tags", [])
            created = pulse.get("created", "")
            modified = pulse.get("modified", "")
            adversary = pulse.get("adversary", "")
            tlp = pulse.get("TLP", "green").upper()
            indicators = pulse.get("indicators", [])

            published_at = None
            if created:
                try:
                    published_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            # Map TLP
            tlp_map = {
                "RED": "TLP:RED",
                "AMBER": "TLP:AMBER",
                "GREEN": "TLP:GREEN",
                "WHITE": "TLP:CLEAR",
            }
            tlp_value = tlp_map.get(tlp, "TLP:GREEN")

            # Extract IOC types and CVEs
            cve_ids = []
            ioc_types = set()
            for ind in indicators:
                itype = ind.get("type", "")
                if itype.startswith("CVE"):
                    cve_ids.append(ind.get("indicator", ""))
                ioc_types.add(itype)

            # Determine asset type & severity
            asset_type = "other"
            if any("IPv" in t for t in ioc_types):
                asset_type = "ip"
            elif any("domain" in t for t in ioc_types):
                asset_type = "domain"
            elif any("URL" in t for t in ioc_types):
                asset_type = "url"
            elif any("hash" in t.lower() or "FileHash" in t for t in ioc_types):
                asset_type = "hash_sha256"

            # Severity based on indicator count
            if len(indicators) > 100:
                severity = "critical"
            elif len(indicators) > 50:
                severity = "high"
            elif len(indicators) > 10:
                severity = "medium"
            else:
                severity = "low"

            full_tags = tags[:10] + (["apt"] if adversary else [])
            targeted_countries = pulse.get("targeted_countries", [])
            industries = pulse.get("industries", [])

            items.append({
                "id": uuid.uuid4(),
                "title": f"[OTX] {name[:200]}",
                "summary": description[:500] if description else f"OTX Pulse with {len(indicators)} indicators",
                "description": description,
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,
                "confidence": 65,
                "source_name": "OTX",
                "source_url": f"https://otx.alienvault.com/pulse/{pulse_id}",
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": pulse_id,
                "feed_type": "ioc",
                "asset_type": asset_type,
                "tlp": tlp_value,
                "tags": full_tags,
                "geo": targeted_countries[:10],
                "industries": industries[:10],
                "cve_ids": cve_ids[:20],
                "affected_products": [],
                "related_ioc_count": len(indicators),
                "is_kev": False,
                "exploit_available": False,
                "exploitability_score": None,
                "source_hash": self.generate_hash("otx", pulse_id),
            })

        return items
