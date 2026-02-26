"""VirusTotal feed connector — fetches popular/recent threat indicators via VT APIv3.

Free tier: 500 requests/day, 4 requests/minute.
Fetches recently trending files, URLs, and domains seen by VT.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalConnector(BaseFeedConnector):
    FEED_NAME = "virustotal"
    SOURCE_RELIABILITY = 85

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        if not settings.virustotal_api_key:
            logger.warning("virustotal_no_api_key")
            return []

        headers = {"x-apikey": settings.virustotal_api_key}

        all_items: list[dict] = []

        # 1. Fetch popular threat actors / trending threats via "popular_threat_categories"
        #    Use /intelligence/search to find recently submitted malicious files
        search_queries = [
            "engines:5+ type:file last_submission_date:1d+",
            "engines:5+ type:url last_submission_date:1d+",
        ]

        for query in search_queries:
            try:
                url = f"{VT_BASE_URL}/intelligence/search"
                params = {"query": query, "limit": 50}
                response = await self.client.get(url, headers=headers, params=params)

                if response.status_code == 401:
                    logger.warning("virustotal_unauthorized — check API key")
                    return []

                if response.status_code == 429:
                    logger.warning("virustotal_rate_limited")
                    break

                # 403 means the endpoint requires premium — fall back to public endpoints
                if response.status_code == 403:
                    logger.info("virustotal_intelligence_not_available, falling_back_to_public")
                    break

                if response.status_code == 200:
                    data = response.json()
                    items = data.get("data", [])
                    all_items.extend(items)
            except Exception as e:
                logger.error("virustotal_search_error", error=str(e))

        # 2. Fallback: Fetch from the public "popular threat" feed endpoints
        if not all_items:
            fallback_endpoints = [
                f"{VT_BASE_URL}/files",           # not available without hash — skip
                f"{VT_BASE_URL}/popular_threat_categories",
            ]

            # Use /ip_addresses and /urls with known-bad samples
            # Instead, use the "livehunt" or "feeds" available on free tier
            # Most practical free-tier approach: search for recent IOCs via comments
            try:
                url = f"{VT_BASE_URL}/comments"
                params = {"limit": 40}
                response = await self.client.get(
                    f"{VT_BASE_URL}/popular_threat_categories",
                    headers=headers,
                )
                if response.status_code == 200:
                    data = response.json()
                    categories = data.get("data", [])
                    for cat in categories[:5]:
                        cat_id = cat.get("id", "")
                        try:
                            cat_resp = await self.client.get(
                                f"{VT_BASE_URL}/popular_threat_categories/{cat_id}/popular_threat_files",
                                headers=headers,
                                params={"limit": 20},
                            )
                            if cat_resp.status_code == 200:
                                cat_data = cat_resp.json()
                                all_items.extend(cat_data.get("data", []))
                        except Exception:
                            pass
            except Exception as e:
                logger.error("virustotal_fallback_error", error=str(e))

        # 3. Final fallback: use /feeds/files endpoint (available on some plans)
        if not all_items:
            try:
                # Get recently submitted files via a time-based cursor
                cursor = last_cursor or ""
                url = f"{VT_BASE_URL}/feeds/files/{cursor}" if cursor else None
                if url:
                    response = await self.client.get(url, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        all_items.extend(data.get("data", []))
            except Exception as e:
                logger.debug("virustotal_feeds_fallback", error=str(e))

        logger.info("virustotal_fetch", total=len(all_items))
        return all_items

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            try:
                item = self._normalize_item(raw)
                if item:
                    items.append(item)
            except Exception as e:
                logger.debug("virustotal_normalize_skip", error=str(e))
                continue

        return items

    def _normalize_item(self, raw: dict) -> dict | None:
        """Normalize a single VT API object into unified intel format."""
        item_type = raw.get("type", "file")
        attrs = raw.get("attributes", {})
        item_id = raw.get("id", "")

        if not item_id:
            return None

        # Extract detection stats
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        total_engines = malicious + suspicious + undetected + last_analysis.get("harmless", 0)

        # Determine severity based on detection ratio
        detection_ratio = (malicious + suspicious) / max(total_engines, 1)
        if detection_ratio >= 0.6:
            severity = "critical"
        elif detection_ratio >= 0.3:
            severity = "high"
        elif detection_ratio >= 0.1:
            severity = "medium"
        else:
            severity = "low"

        confidence = min(int(detection_ratio * 100), 100)

        # Extract meaningful name
        meaningful_name = attrs.get("meaningful_name", "")
        names = attrs.get("names", [])
        type_description = attrs.get("type_description", "")

        # Build title
        if item_type == "file":
            sha256 = attrs.get("sha256", item_id)
            display_name = meaningful_name or (names[0] if names else sha256[:16])
            title = f"[VirusTotal] Malicious File: {display_name}"
            asset_type = "hash_sha256"
            source_ref = sha256
            source_url = f"https://www.virustotal.com/gui/file/{sha256}"
        elif item_type == "url":
            url_value = attrs.get("url", item_id)
            title = f"[VirusTotal] Malicious URL: {url_value[:100]}"
            asset_type = "url"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/url/{item_id}"
        elif item_type == "domain":
            title = f"[VirusTotal] Malicious Domain: {item_id}"
            asset_type = "domain"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/domain/{item_id}"
        elif item_type == "ip_address":
            title = f"[VirusTotal] Malicious IP: {item_id}"
            asset_type = "ip"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/ip-address/{item_id}"
        else:
            title = f"[VirusTotal] Threat: {item_id[:80]}"
            asset_type = "other"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/search/{item_id}"

        # Timestamps
        first_seen = attrs.get("first_submission_date") or attrs.get("creation_date")
        published_at = None
        if first_seen:
            try:
                published_at = datetime.fromtimestamp(first_seen, tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                pass

        # Tags from VT
        vt_tags = attrs.get("tags", [])
        popular_threat = attrs.get("popular_threat_classification", {})
        threat_label = popular_threat.get("suggested_threat_label", "")
        threat_category = popular_threat.get("popular_threat_category", [])

        tags = ["virustotal", severity]
        if threat_label:
            tags.append(threat_label)
        for cat in threat_category[:3]:
            cat_val = cat.get("value", "")
            if cat_val:
                tags.append(cat_val)
        tags.extend(vt_tags[:5])

        # Summary
        summary = (
            f"Detection: {malicious}/{total_engines} engines | "
            f"Type: {type_description or item_type}"
        )
        if threat_label:
            summary += f" | Threat: {threat_label}"

        description = summary
        if names:
            description += f"\nKnown names: {', '.join(names[:5])}"

        return {
            "id": uuid.uuid4(),
            "title": title[:500],
            "summary": summary[:500],
            "description": description[:2000],
            "published_at": published_at,
            "ingested_at": self.now_utc(),
            "updated_at": self.now_utc(),
            "severity": severity,
            "risk_score": 0,
            "confidence": confidence,
            "source_name": "VirusTotal",
            "source_url": source_url,
            "source_reliability": self.SOURCE_RELIABILITY,
            "source_ref": source_ref,
            "feed_type": "ioc",
            "asset_type": asset_type,
            "tlp": "TLP:CLEAR",
            "tags": tags[:15],
            "geo": [],
            "industries": [],
            "cve_ids": [],
            "affected_products": [],
            "related_ioc_count": malicious,
            "is_kev": False,
            "exploit_available": False,
            "exploitability_score": None,
            "source_hash": self.generate_hash("virustotal", source_ref),
        }
