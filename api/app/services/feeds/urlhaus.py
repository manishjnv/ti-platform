"""URLhaus (abuse.ch) feed connector."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


class URLhausConnector(BaseFeedConnector):
    FEED_NAME = "urlhaus"
    SOURCE_RELIABILITY = 75

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        response = await self.client.get(URLHAUS_CSV_URL)
        response.raise_for_status()

        text = response.text
        # Skip comment lines
        lines = [l for l in text.strip().split("\n") if not l.startswith("#")]
        if not lines:
            return []

        reader = csv.DictReader(
            io.StringIO("\n".join(lines)),
            fieldnames=[
                "id", "dateadded", "url", "url_status", "last_online",
                "threat", "tags", "urlhaus_link", "reporter"
            ],
        )

        items = list(reader)
        logger.info("urlhaus_fetch", total=len(items))

        # Incremental filter
        if last_cursor:
            try:
                cursor_dt = datetime.fromisoformat(last_cursor)
                items = [
                    i for i in items
                    if self._parse_date(i.get("dateadded")) and
                    self._parse_date(i.get("dateadded")) > cursor_dt
                ]
            except (ValueError, TypeError):
                pass

        return items[:500]  # Limit batch size

    def _parse_date(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            url = raw.get("url", "")
            if not url:
                continue

            threat = raw.get("threat", "unknown")
            status = raw.get("url_status", "unknown")
            tags_str = raw.get("tags", "")
            tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []
            tags.append("malware_url")

            published_at = self._parse_date(raw.get("dateadded"))

            severity = "high" if status == "online" else "medium"

            items.append({
                "id": uuid.uuid4(),
                "title": f"[URLhaus] Malicious URL: {url[:100]}",
                "summary": f"Threat: {threat} | Status: {status} | Reporter: {raw.get('reporter', 'N/A')}",
                "description": f"Malicious URL detected by URLhaus. URL: {url}. Threat type: {threat}.",
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,
                "confidence": 70,
                "source_name": "URLhaus",
                "source_url": raw.get("urlhaus_link", "https://urlhaus.abuse.ch"),
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": raw.get("id", ""),
                "feed_type": "ioc",
                "asset_type": "url",
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
                "source_hash": self.generate_hash("urlhaus", url),
            })

        return items
