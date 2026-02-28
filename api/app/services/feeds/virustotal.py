"""VirusTotal feed connector — free-tier compatible.

Strategy: Fetches seed IOCs from lightweight public threat lists (Feodo Tracker
C2 IPs, abuse.ch malware hashes), then enriches a small batch via VT's
individual-lookup endpoints which are available on the free tier.

Free tier limits: 4 requests/minute, 500 requests/day.
We use ~12 lookups per 15-min cycle with 16 s spacing ≈ 3 min of wall time.
"""

from __future__ import annotations

import asyncio
import random
import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

VT_BASE = "https://www.virustotal.com/api/v3"

# Lightweight public threat-intel seed sources (plain-text, no auth)
FEODO_C2_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
BAZAAR_RECENT_URL = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

# Delay between VT API calls (16 s keeps us under 4 req/min)
VT_CALL_DELAY = 16
# Max VT lookups per cycle (IP + hash combined)
MAX_IP_LOOKUPS = 6
MAX_HASH_LOOKUPS = 6


class VirusTotalConnector(BaseFeedConnector):
    FEED_NAME = "virustotal"
    SOURCE_RELIABILITY = 85

    # ------------------------------------------------------------------
    # fetch
    # ------------------------------------------------------------------
    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        if not settings.virustotal_api_key:
            logger.warning("virustotal_no_api_key")
            return []

        headers = {"x-apikey": settings.virustotal_api_key}
        all_items: list[dict] = []

        # Parse cursor for rotation offsets
        ip_offset, hash_offset = 0, 0
        if last_cursor:
            try:
                parts = last_cursor.split("|")
                ip_offset = int(parts[0])
                hash_offset = int(parts[1]) if len(parts) > 1 else 0
            except (ValueError, IndexError):
                pass

        # 1. Fetch seed IOCs from public threat lists (in parallel)
        seed_ips, seed_hashes = await asyncio.gather(
            self._fetch_feodo_ips(),
            self._fetch_bazaar_hashes(),
        )

        # Rotate through the lists using offsets so we don't re-lookup
        # the same indicators every cycle
        if seed_ips:
            ip_offset = ip_offset % len(seed_ips)
            batch_ips = seed_ips[ip_offset : ip_offset + MAX_IP_LOOKUPS]
            if len(batch_ips) < MAX_IP_LOOKUPS:
                batch_ips += seed_ips[: MAX_IP_LOOKUPS - len(batch_ips)]
        else:
            batch_ips = []

        if seed_hashes:
            hash_offset = hash_offset % len(seed_hashes)
            batch_hashes = seed_hashes[hash_offset : hash_offset + MAX_HASH_LOOKUPS]
            if len(batch_hashes) < MAX_HASH_LOOKUPS:
                batch_hashes += seed_hashes[: MAX_HASH_LOOKUPS - len(batch_hashes)]
        else:
            batch_hashes = []

        logger.info(
            "virustotal_seeds",
            total_ips=len(seed_ips),
            total_hashes=len(seed_hashes),
            batch_ips=len(batch_ips),
            batch_hashes=len(batch_hashes),
        )

        # 2. Lookup IPs on VT
        call_count = 0
        for ip in batch_ips:
            if call_count > 0:
                await asyncio.sleep(VT_CALL_DELAY)
            item = await self._vt_ip_lookup(ip, headers)
            if item:
                all_items.append(item)
            call_count += 1

        # 3. Lookup hashes on VT
        for sha in batch_hashes:
            if call_count > 0:
                await asyncio.sleep(VT_CALL_DELAY)
            item = await self._vt_file_lookup(sha, headers)
            if item:
                all_items.append(item)
            call_count += 1

        # Store new cursor offsets for next cycle
        new_ip_offset = ip_offset + MAX_IP_LOOKUPS
        new_hash_offset = hash_offset + MAX_HASH_LOOKUPS
        # We stash the cursor text in _vt_cursor so the task pipeline can read it
        self._next_cursor = f"{new_ip_offset}|{new_hash_offset}"

        logger.info("virustotal_fetch", total=len(all_items), lookups=call_count)
        return all_items

    # ------------------------------------------------------------------
    # Seed fetchers
    # ------------------------------------------------------------------
    async def _fetch_feodo_ips(self) -> list[str]:
        """Return active C2 server IPs from Feodo Tracker (free, no auth)."""
        try:
            resp = await self.client.get(FEODO_C2_URL, timeout=20)
            if resp.status_code != 200:
                logger.warning("feodo_fetch_failed", status=resp.status_code)
                return []
            ips = [
                line.strip()
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            random.shuffle(ips)  # shuffle so rotation covers diverse C2 infra
            return ips
        except Exception as e:
            logger.error("feodo_seed_error", error=str(e))
            return []

    async def _fetch_bazaar_hashes(self) -> list[str]:
        """Return recent malware SHA-256 hashes from MalwareBazaar (free, no auth)."""
        try:
            resp = await self.client.get(BAZAAR_RECENT_URL, timeout=20)
            if resp.status_code != 200:
                logger.warning("bazaar_fetch_failed", status=resp.status_code)
                return []
            hashes = [
                line.strip()
                for line in resp.text.splitlines()
                if line.strip() and not line.startswith("#") and len(line.strip()) == 64
            ]
            random.shuffle(hashes)
            return hashes[:200]  # cap to avoid huge list
        except Exception as e:
            logger.error("bazaar_seed_error", error=str(e))
            return []

    # ------------------------------------------------------------------
    # VT individual lookups
    # ------------------------------------------------------------------
    async def _vt_ip_lookup(self, ip: str, headers: dict) -> dict | None:
        """Look up a single IP on VT.  Returns raw VT data dict or None."""
        try:
            resp = await self.client.get(f"{VT_BASE}/ip_addresses/{ip}", headers=headers)
            if resp.status_code == 429:
                logger.warning("virustotal_rate_limited")
                return None
            if resp.status_code == 401:
                logger.warning("virustotal_unauthorized")
                return None
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            data["_lookup_type"] = "ip_address"
            data["_lookup_value"] = ip
            data["_seed_source"] = "feodo_c2"
            return data
        except Exception as e:
            logger.debug("vt_ip_lookup_error", ip=ip, error=str(e))
            return None

    async def _vt_file_lookup(self, sha256: str, headers: dict) -> dict | None:
        """Look up a single SHA-256 hash on VT.  Returns raw VT data dict or None."""
        try:
            resp = await self.client.get(f"{VT_BASE}/files/{sha256}", headers=headers)
            if resp.status_code == 429:
                logger.warning("virustotal_rate_limited")
                return None
            if resp.status_code == 401:
                logger.warning("virustotal_unauthorized")
                return None
            if resp.status_code != 200:
                return None
            data = resp.json().get("data", {})
            data["_lookup_type"] = "file"
            data["_lookup_value"] = sha256
            data["_seed_source"] = "malwarebazaar"
            return data
        except Exception as e:
            logger.debug("vt_file_lookup_error", sha256=sha256[:16], error=str(e))
            return None

    # ------------------------------------------------------------------
    # normalize
    # ------------------------------------------------------------------
    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            try:
                item = self._normalize_item(raw)
                if item:
                    items.append(item)
            except Exception as e:
                logger.debug("virustotal_normalize_skip", error=str(e))
        return items

    def _normalize_item(self, raw: dict) -> dict | None:
        """Normalize a single VT API response into the unified intel format."""
        item_type = raw.get("type", raw.get("_lookup_type", "file"))
        attrs = raw.get("attributes", {})
        item_id = raw.get("id", raw.get("_lookup_value", ""))
        seed_source = raw.get("_seed_source", "")

        if not item_id:
            return None

        # Detection stats
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        undetected = last_analysis.get("undetected", 0)
        harmless = last_analysis.get("harmless", 0)
        total_engines = malicious + suspicious + undetected + harmless

        # Skip items with no meaningful detection data
        if total_engines == 0:
            return None

        detection_ratio = (malicious + suspicious) / max(total_engines, 1)

        # Severity
        if detection_ratio >= 0.6:
            severity = "critical"
        elif detection_ratio >= 0.3:
            severity = "high"
        elif detection_ratio >= 0.1:
            severity = "medium"
        else:
            severity = "low"

        confidence = min(int(detection_ratio * 100), 100)

        # Type-specific fields
        meaningful_name = attrs.get("meaningful_name", "")
        names = attrs.get("names", [])
        type_desc = attrs.get("type_description", "")

        if item_type == "file":
            sha256 = attrs.get("sha256", item_id)
            display = meaningful_name or (names[0] if names else sha256[:16])
            title = f"[VirusTotal] Malicious File: {display}"
            asset_type = "hash_sha256"
            source_ref = sha256
            source_url = f"https://www.virustotal.com/gui/file/{sha256}"
        elif item_type == "ip_address":
            title = f"[VirusTotal] Malicious IP: {item_id}"
            asset_type = "ip"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/ip-address/{item_id}"
        elif item_type == "domain":
            title = f"[VirusTotal] Malicious Domain: {item_id}"
            asset_type = "domain"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/domain/{item_id}"
        elif item_type == "url":
            url_val = attrs.get("url", item_id)
            title = f"[VirusTotal] Malicious URL: {url_val[:100]}"
            asset_type = "url"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/url/{item_id}"
        else:
            title = f"[VirusTotal] Threat: {item_id[:80]}"
            asset_type = "other"
            source_ref = item_id
            source_url = f"https://www.virustotal.com/gui/search/{item_id}"

        # Timestamps
        published_at = None
        first_seen = attrs.get("first_submission_date") or attrs.get("creation_date")
        if first_seen:
            try:
                published_at = datetime.fromtimestamp(first_seen, tz=timezone.utc)
            except (ValueError, TypeError, OSError):
                pass

        # Tags
        vt_tags = attrs.get("tags", [])
        popular_threat = attrs.get("popular_threat_classification") or {}
        threat_label = popular_threat.get("suggested_threat_label", "")
        threat_cats = popular_threat.get("popular_threat_category") or []

        tags = ["virustotal", severity]
        if seed_source:
            tags.append(seed_source)
        if threat_label:
            tags.append(threat_label)
        for cat in threat_cats[:3]:
            if isinstance(cat, dict):
                val = cat.get("value", "")
            else:
                val = str(cat)
            if val:
                tags.append(val)
        tags.extend(vt_tags[:5])

        # Summary
        summary = f"Detection: {malicious}/{total_engines} engines | Type: {type_desc or item_type}"
        if threat_label:
            summary += f" | Threat: {threat_label}"
        description = summary
        if names:
            description += f"\nKnown names: {', '.join(names[:5])}"

        # Country / AS info for IPs
        geo = []
        country = attrs.get("country")
        if country:
            geo.append(country)

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
            "geo": geo,
            "industries": [],
            "cve_ids": [],
            "affected_products": [],
            "related_ioc_count": malicious,
            "is_kev": False,
            "exploit_available": False,
            "exploitability_score": None,
            "source_hash": self.generate_hash("virustotal", source_ref),
        }
