"""Shodan feed connector — fetches exposed services, honeypot data, and vulnerabilities.

Free tier: 1 request/second, limited search credits.
Fetches recently discovered exposed services and known vulnerabilities.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

SHODAN_BASE_URL = "https://api.shodan.io"
SHODAN_EXPLOITS_URL = "https://exploits.shodan.io/api"


class ShodanConnector(BaseFeedConnector):
    FEED_NAME = "shodan"
    SOURCE_RELIABILITY = 80

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        if not settings.shodan_api_key:
            logger.warning("shodan_no_api_key")
            return []

        api_key = settings.shodan_api_key
        all_items: list[dict] = []

        # 1. Fetch recently discovered exploits/vulns
        try:
            url = f"{SHODAN_EXPLOITS_URL}/search"
            params = {
                "query": "type:exploit",
                "key": api_key,
            }
            response = await self.client.get(url, params=params)

            if response.status_code == 401:
                logger.warning("shodan_unauthorized — check API key")
                return []

            if response.status_code == 429:
                logger.warning("shodan_rate_limited")
            elif response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                for match in matches[:100]:
                    match["_shodan_type"] = "exploit"
                all_items.extend(matches[:100])
        except Exception as e:
            logger.error("shodan_exploits_error", error=str(e))

        # 2. Fetch honeypot/exposed services via search
        try:
            url = f"{SHODAN_BASE_URL}/shodan/host/search"
            params = {
                "query": "vuln:cve-2024",
                "key": api_key,
            }
            response = await self.client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                for match in matches[:100]:
                    match["_shodan_type"] = "host"
                all_items.extend(matches[:100])
            elif response.status_code == 402:
                # Search requires paid plan — try alternative
                logger.info("shodan_search_requires_upgrade, trying_alternatives")
        except Exception as e:
            logger.error("shodan_search_error", error=str(e))

        # 3. Fallback: Fetch known exploits for recent CVEs
        if not all_items:
            recent_cve_years = ["2024", "2025"]
            for year in recent_cve_years:
                try:
                    url = f"{SHODAN_EXPLOITS_URL}/search"
                    params = {
                        "query": f"cve-{year}",
                        "key": api_key,
                    }
                    response = await self.client.get(url, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        matches = data.get("matches", [])
                        for match in matches[:50]:
                            match["_shodan_type"] = "exploit"
                        all_items.extend(matches[:50])
                except Exception as e:
                    logger.debug("shodan_cve_fallback_error", error=str(e))
                    continue

        # 4. Fetch exposed ports / honeypots via /shodan/ports
        try:
            url = f"{SHODAN_BASE_URL}/shodan/ports"
            params = {"key": api_key}
            response = await self.client.get(url, params=params)
            if response.status_code == 200:
                # This returns a list of port numbers — useful metadata but not items
                ports = response.json()
                logger.info("shodan_active_ports", count=len(ports))
        except Exception:
            pass

        logger.info("shodan_fetch", total=len(all_items))
        return all_items

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            try:
                shodan_type = raw.get("_shodan_type", "exploit")
                if shodan_type == "exploit":
                    item = self._normalize_exploit(raw)
                else:
                    item = self._normalize_host(raw)
                if item:
                    items.append(item)
            except Exception as e:
                logger.debug("shodan_normalize_skip", error=str(e))
                continue

        return items

    def _normalize_exploit(self, raw: dict) -> dict | None:
        """Normalize a Shodan exploit entry."""
        description = raw.get("description", "")
        source = raw.get("source", "")
        exploit_id = raw.get("_id", raw.get("id", ""))
        code = raw.get("code", "")
        platform = raw.get("platform", "")
        exploit_type = raw.get("type", "")
        port = raw.get("port", 0)
        author = raw.get("author", "")

        if not exploit_id:
            return None

        # Extract CVEs
        cve_ids = []
        cve_list = raw.get("cve", [])
        if isinstance(cve_list, list):
            cve_ids = [c for c in cve_list if isinstance(c, str) and c.startswith("CVE-")][:20]

        # Date
        date_str = raw.get("date", "")
        published_at = None
        if date_str:
            try:
                published_at = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                try:
                    published_at = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    pass

        # Severity — exploits are higher severity by nature
        severity = "high"
        if any("remote" in str(v).lower() for v in [exploit_type, description]):
            severity = "critical"
        elif any("local" in str(v).lower() for v in [exploit_type, description]):
            severity = "medium"

        title_text = description[:150] if description else f"Exploit {exploit_id}"
        title = f"[Shodan] {title_text}"

        tags = ["shodan", "exploit", severity]
        if platform:
            tags.append(platform.lower())
        if exploit_type:
            tags.append(exploit_type.lower())

        summary = f"Source: {source} | Platform: {platform or 'N/A'} | Type: {exploit_type or 'N/A'}"
        if author:
            summary += f" | Author: {author}"

        full_description = description
        if code:
            full_description += f"\n\nExploit code available ({len(code)} chars)"

        return {
            "id": uuid.uuid4(),
            "title": title[:500],
            "summary": summary[:500],
            "description": full_description[:2000],
            "published_at": published_at,
            "ingested_at": self.now_utc(),
            "updated_at": self.now_utc(),
            "severity": severity,
            "risk_score": 0,
            "confidence": 75,
            "source_name": "Shodan",
            "source_url": f"https://exploits.shodan.io/?q={exploit_id}",
            "source_reliability": self.SOURCE_RELIABILITY,
            "source_ref": str(exploit_id),
            "feed_type": "exploit",
            "asset_type": "other",
            "tlp": "TLP:CLEAR",
            "tags": tags[:15],
            "geo": [],
            "industries": [],
            "cve_ids": cve_ids,
            "affected_products": [platform] if platform else [],
            "related_ioc_count": len(cve_ids),
            "is_kev": False,
            "exploit_available": True,
            "exploitability_score": None,
            "source_hash": self.generate_hash("shodan_exploit", str(exploit_id)),
        }

    def _normalize_host(self, raw: dict) -> dict | None:
        """Normalize a Shodan host/service entry."""
        ip = raw.get("ip_str", "")
        port = raw.get("port", 0)
        transport = raw.get("transport", "tcp")
        product = raw.get("product", "")
        version = raw.get("version", "")
        org = raw.get("org", "")
        os_name = raw.get("os", "")
        country_code = raw.get("location", {}).get("country_code", "")
        city = raw.get("location", {}).get("city", "")
        vulns = raw.get("vulns", {})

        if not ip:
            return None

        # CVEs from vulns
        cve_ids = [k for k in vulns.keys() if k.startswith("CVE-")][:20] if isinstance(vulns, dict) else []

        # Severity based on vulnerability count
        vuln_count = len(cve_ids) if cve_ids else 0
        if vuln_count >= 10:
            severity = "critical"
        elif vuln_count >= 5:
            severity = "high"
        elif vuln_count >= 1:
            severity = "medium"
        else:
            severity = "low"

        service_str = f"{product} {version}".strip() if product else f"port {port}/{transport}"
        title = f"[Shodan] Exposed Service: {ip}:{port} ({service_str})"

        tags = ["shodan", "exposed_service", severity]
        if product:
            tags.append(product.lower())
        if os_name:
            tags.append(os_name.lower())

        geo = []
        if country_code:
            geo.append(country_code)
        if city:
            geo.append(city)

        summary = f"IP: {ip} | Port: {port}/{transport} | Service: {service_str}"
        if org:
            summary += f" | Org: {org}"
        if vuln_count > 0:
            summary += f" | Vulns: {vuln_count}"

        # Published timestamp
        timestamp = raw.get("timestamp", "")
        published_at = None
        if timestamp:
            try:
                published_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        description = f"Exposed service on {ip}:{port}/{transport}"
        if product:
            description += f"\nProduct: {product}"
        if version:
            description += f" v{version}"
        if org:
            description += f"\nOrganization: {org}"
        if os_name:
            description += f"\nOS: {os_name}"
        if cve_ids:
            description += f"\nVulnerabilities: {', '.join(cve_ids[:10])}"

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
            "confidence": 70,
            "source_name": "Shodan",
            "source_url": f"https://www.shodan.io/host/{ip}",
            "source_reliability": self.SOURCE_RELIABILITY,
            "source_ref": f"{ip}:{port}",
            "feed_type": "ioc",
            "asset_type": "ip",
            "tlp": "TLP:CLEAR",
            "tags": tags[:15],
            "geo": geo[:10],
            "industries": [],
            "cve_ids": cve_ids,
            "affected_products": [f"{product} {version}".strip()] if product else [],
            "related_ioc_count": vuln_count,
            "is_kev": False,
            "exploit_available": vuln_count > 0,
            "exploitability_score": None,
            "source_hash": self.generate_hash("shodan_host", ip, str(port)),
        }
