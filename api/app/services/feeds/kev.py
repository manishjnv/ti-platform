"""CISA KEV (Known Exploited Vulnerabilities) feed connector."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVConnector(BaseFeedConnector):
    FEED_NAME = "cisa_kev"
    SOURCE_RELIABILITY = 95

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        response = await self.client.get(KEV_URL)
        response.raise_for_status()
        data = response.json()

        vulns = data.get("vulnerabilities", [])
        logger.info("kev_fetch", total=len(vulns))

        # Incremental: filter by dateAdded if we have a cursor
        if last_cursor:
            try:
                cursor_date = datetime.fromisoformat(last_cursor)
                vulns = [
                    v for v in vulns
                    if datetime.fromisoformat(v.get("dateAdded", "2000-01-01")) > cursor_date
                ]
            except (ValueError, TypeError):
                pass

        return vulns

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for vuln in raw_items:
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            name = vuln.get("vulnerabilityName", "")
            desc = vuln.get("shortDescription", "")
            date_added = vuln.get("dateAdded", "")
            due_date = vuln.get("dueDate", "")
            action = vuln.get("requiredAction", "")
            known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

            published_at = None
            if date_added:
                try:
                    published_at = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    pass

            severity = "critical"  # All KEV entries are critical by definition

            title = f"[KEV] {cve_id}: {name}" if name else f"[KEV] {cve_id}"
            summary = desc
            if action:
                summary += f" | Required Action: {action}"
            if due_date:
                summary += f" | Due: {due_date}"

            tags = ["kev", "critical", "exploited"]
            if known_ransomware.lower() == "known":
                tags.append("ransomware")

            items.append({
                "id": uuid.uuid4(),
                "title": title,
                "summary": summary[:500],
                "description": desc,
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,
                "confidence": 95,
                "source_name": "CISA KEV",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": cve_id,
                "feed_type": "vulnerability",
                "asset_type": "cve",
                "tlp": "TLP:CLEAR",
                "tags": tags,
                "geo": ["US"],
                "industries": [],
                "cve_ids": [cve_id],
                "affected_products": [f"{vendor} {product}"] if vendor else [],
                "related_ioc_count": 0,
                "is_kev": True,
                "exploit_available": True,
                "exploitability_score": 10.0,
                "source_hash": self.generate_hash("kev", cve_id),
            })

        return items
