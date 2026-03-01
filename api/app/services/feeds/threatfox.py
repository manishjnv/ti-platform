"""ThreatFox (abuse.ch) feed connector — malware IOCs (C2, botnet, payload).

Free, no API key required. Uses the JSON export endpoint.
Docs: https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)

# The POST API returns 401 from some IPs; the export endpoint is always free
THREATFOX_EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent/"

# Map ThreatFox ioc_type → our asset_type enum
_TYPE_MAP = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash_md5",
    "sha256_hash": "hash_sha256",
}

_SEVERITY_MAP = {
    "high": "critical",
    "medium": "high",
    "low": "medium",
}


class ThreatFoxConnector(BaseFeedConnector):
    FEED_NAME = "threatfox"
    SOURCE_RELIABILITY = 80

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        """Fetch recent IOCs from ThreatFox JSON export."""
        response = await self.client.get(THREATFOX_EXPORT_URL)
        response.raise_for_status()
        data = response.json()

        # Export format: {id_str: [list_of_ioc_dicts], ...}
        items = []
        for ioc_id, entries in data.items():
            if isinstance(entries, list):
                for entry in entries:
                    entry["id"] = ioc_id
                    items.append(entry)

        logger.info("threatfox_fetch", total=len(items))

        # Incremental: filter by first_seen > last_cursor
        if last_cursor:
            try:
                cursor_dt = datetime.fromisoformat(last_cursor)
                items = [
                    i for i in items
                    if self._parse_date(i.get("first_seen_utc"))
                    and self._parse_date(i.get("first_seen_utc")) > cursor_dt
                ]
            except (ValueError, TypeError):
                pass

        return items[:500]

    def _parse_date(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
        return None

    def _clean_ioc_value(self, ioc: str, ioc_type: str) -> str:
        """Strip port from ip:port style IOCs."""
        if ioc_type == "ip:port" and ":" in ioc:
            return ioc.rsplit(":", 1)[0]
        return ioc

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            # Export uses "ioc_value", API uses "ioc" — support both
            ioc_value = raw.get("ioc_value") or raw.get("ioc", "")
            if not ioc_value:
                continue

            ioc_type_raw = raw.get("ioc_type", "")
            asset_type = _TYPE_MAP.get(ioc_type_raw, "other")
            clean_value = self._clean_ioc_value(ioc_value, ioc_type_raw)

            threat_type = raw.get("threat_type", "unknown")
            malware = raw.get("malware_printable", "unknown")
            confidence = raw.get("confidence_level", 50) or 50

            # Tags: export returns comma-separated string, API returns list
            tags_raw = raw.get("tags") or []
            if isinstance(tags_raw, str):
                tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
            else:
                tags = list(tags_raw)
            tags.append("threatfox")
            if malware and malware != "unknown":
                tags.append(malware.lower().replace(" ", "_"))

            published_at = self._parse_date(raw.get("first_seen_utc"))

            # Map ThreatFox threat_type_desc to severity
            tl = raw.get("threat_type_desc", "").lower()
            if "botnet" in tl or "c2" in tl or "payload" in tl:
                severity = "critical"
            elif "payload_delivery" in tl:
                severity = "high"
            else:
                severity = _SEVERITY_MAP.get(
                    (raw.get("confidence_level") or 0) > 70 and "high" or "medium",
                    "medium",
                )

            items.append({
                "id": uuid.uuid4(),
                "title": f"[ThreatFox] {threat_type}: {clean_value[:80]}",
                "summary": f"Malware: {malware} | Type: {threat_type} | Confidence: {confidence}%",
                "description": (
                    f"ThreatFox IOC — {ioc_value}. Malware family: {malware}. "
                    f"Threat type: {raw.get('threat_type_desc', 'N/A')}. "
                    f"Reporter: {raw.get('reporter', 'N/A')}."
                ),
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,
                "confidence": min(confidence, 100),
                "source_name": "ThreatFox",
                "source_url": f"https://threatfox.abuse.ch/ioc/{raw.get('id', '')}",
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": str(raw.get("id", "")),
                "feed_type": "ioc",
                "asset_type": asset_type,
                "tlp": "TLP:CLEAR",
                "tags": tags,
                "geo": [],
                "industries": [],
                "cve_ids": [],
                "affected_products": [],
                "related_ioc_count": 1,
                "is_kev": False,
                "exploit_available": False,
                "exploitability_score": None,
                "source_hash": self.generate_hash("threatfox", ioc_value),
            })

        return items
