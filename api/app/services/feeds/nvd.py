"""NVD (National Vulnerability Database) feed connector."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDConnector(BaseFeedConnector):
    FEED_NAME = "nvd"
    SOURCE_RELIABILITY = 90

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        params: dict = {
            "resultsPerPage": 100,
            "startIndex": 0,
        }

        # Incremental: fetch CVEs modified since last cursor
        if last_cursor:
            params["lastModStartDate"] = last_cursor
            params["lastModEndDate"] = self.now_utc().strftime("%Y-%m-%dT%H:%M:%S.000")
        else:
            # First run: only recent
            params["pubStartDate"] = "2024-01-01T00:00:00.000"
            params["pubEndDate"] = self.now_utc().strftime("%Y-%m-%dT%H:%M:%S.000")

        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        response = await self.client.get(NVD_API_URL, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

        logger.info("nvd_fetch", total=data.get("totalResults", 0))
        return data.get("vulnerabilities", [])

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for vuln in raw_items:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity = "unknown"

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    sev = cvss_data.get("baseSeverity", "unknown").lower()
                    if sev in ("critical", "high", "medium", "low"):
                        severity = sev
                    break

            # Description
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Published date
            pub_str = cve.get("published", "")
            published_at = None
            if pub_str:
                try:
                    published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass

            # Affected products
            products = []
            configs = cve.get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if criteria:
                            products.append(criteria)

            # Exploit info
            refs = cve.get("references", [])
            exploit_available = any(
                "Exploit" in (ref.get("tags") or []) for ref in refs
            )

            source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            items.append({
                "id": uuid.uuid4(),
                "title": f"{cve_id}: {desc[:200]}" if desc else cve_id,
                "summary": desc[:500] if desc else None,
                "description": desc,
                "published_at": published_at,
                "ingested_at": self.now_utc(),
                "updated_at": self.now_utc(),
                "severity": severity,
                "risk_score": 0,  # Will be computed by scoring service
                "confidence": 85,
                "source_name": "NVD",
                "source_url": source_url,
                "source_reliability": self.SOURCE_RELIABILITY,
                "source_ref": cve_id,
                "feed_type": "vulnerability",
                "asset_type": "cve",
                "tlp": "TLP:CLEAR",
                "tags": [severity, "cve"],
                "geo": [],
                "industries": [],
                "cve_ids": [cve_id],
                "affected_products": products[:10],
                "related_ioc_count": 0,
                "is_kev": False,
                "exploit_available": exploit_available,
                "exploitability_score": cvss_score,
                "source_hash": self.generate_hash("nvd", cve_id),
            })

        return items
