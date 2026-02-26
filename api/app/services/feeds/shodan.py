"""Shodan feed connector — fetches vulnerabilities and exploit data.

Uses Shodan's free APIs:
- CVEDB (cvedb.shodan.io) — CVE database with EPSS, KEV, ransomware intel (no key needed)
- InternetDB (internetdb.shodan.io) — host enrichment (no key needed)
- Shodan API (api.shodan.io) — host lookups (free tier, key required)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.feeds.base import BaseFeedConnector

logger = get_logger(__name__)
settings = get_settings()

CVEDB_URL = "https://cvedb.shodan.io"
SHODAN_BASE_URL = "https://api.shodan.io"


class ShodanConnector(BaseFeedConnector):
    FEED_NAME = "shodan"
    SOURCE_RELIABILITY = 80

    async def fetch(self, last_cursor: str | None = None) -> list[dict]:
        all_items: list[dict] = []

        # 1. CVEDB: High-EPSS CVEs (most likely to be exploited)
        try:
            response = await self.client.get(
                f"{CVEDB_URL}/cves",
                params={"limit": 100, "sort_by_epss": True},
            )
            if response.status_code == 200:
                data = response.json()
                cves = data.get("cves", [])
                for cve in cves:
                    cve["_shodan_type"] = "cvedb"
                all_items.extend(cves)
                logger.info("shodan_cvedb_epss", count=len(cves))
        except Exception as e:
            logger.error("shodan_cvedb_epss_error", error=str(e))

        # 2. CVEDB: KEV entries (known exploited vulns)
        try:
            response = await self.client.get(
                f"{CVEDB_URL}/cves",
                params={"limit": 50, "is_kev": True},
            )
            if response.status_code == 200:
                data = response.json()
                cves = data.get("cves", [])
                # Avoid duplicates — only add CVEs not already fetched
                existing_ids = {item.get("cve_id") for item in all_items}
                new_cves = [c for c in cves if c.get("cve_id") not in existing_ids]
                for cve in new_cves:
                    cve["_shodan_type"] = "cvedb"
                all_items.extend(new_cves)
                logger.info("shodan_cvedb_kev", count=len(new_cves))
        except Exception as e:
            logger.error("shodan_cvedb_kev_error", error=str(e))

        # 3. CVEDB: Recent CVEs with high CVSS
        for year in ["2025", "2024"]:
            try:
                response = await self.client.get(
                    f"{CVEDB_URL}/cves",
                    params={"limit": 30, "sort_by_epss": True, "start_date": f"{year}-01-01"},
                )
                if response.status_code == 200:
                    data = response.json()
                    cves = data.get("cves", [])
                    existing_ids = {item.get("cve_id") for item in all_items}
                    new_cves = [c for c in cves if c.get("cve_id") not in existing_ids]
                    for cve in new_cves:
                        cve["_shodan_type"] = "cvedb"
                    all_items.extend(new_cves)
            except Exception as e:
                logger.debug("shodan_cvedb_year_error", year=year, error=str(e))

        logger.info("shodan_fetch", total=len(all_items))
        return all_items

    def normalize(self, raw_items: list[dict]) -> list[dict]:
        items = []
        for raw in raw_items:
            try:
                shodan_type = raw.get("_shodan_type", "cvedb")
                if shodan_type == "cvedb":
                    item = self._normalize_cvedb(raw)
                else:
                    item = self._normalize_host(raw)
                if item:
                    items.append(item)
            except Exception as e:
                logger.debug("shodan_normalize_skip", error=str(e))
                continue

        return items

    def _normalize_cvedb(self, raw: dict) -> dict | None:
        """Normalize a Shodan CVEDB entry."""
        cve_id = raw.get("cve_id", "")
        if not cve_id:
            return None

        summary_text = raw.get("summary", "")
        cvss = raw.get("cvss", 0) or 0
        cvss_v3 = raw.get("cvss_v3") or cvss
        epss = raw.get("epss", 0) or 0
        ranking_epss = raw.get("ranking_epss", 0) or 0
        is_kev = raw.get("kev", False) or False
        propose_action = raw.get("propose_action", "")
        ransomware = raw.get("ransomware_campaign", "")
        vendor = raw.get("vendor", "")
        product = raw.get("product", "")
        references = raw.get("references", []) or []

        # Severity from CVSS
        if cvss_v3 >= 9.0:
            severity = "critical"
        elif cvss_v3 >= 7.0:
            severity = "high"
        elif cvss_v3 >= 4.0:
            severity = "medium"
        else:
            severity = "low"

        # Boost severity if KEV or high EPSS
        if is_kev and severity in ("medium", "low"):
            severity = "high"
        if epss >= 0.9 and severity == "medium":
            severity = "high"

        # Confidence from EPSS ranking
        confidence = min(int((epss * 70) + (30 if is_kev else 0)), 100)
        if confidence < 20:
            confidence = 20  # Minimum baseline

        # Published timestamp
        published_at = None
        pub_str = raw.get("published_time", "")
        if pub_str:
            try:
                published_at = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        # Title
        title = f"[Shodan CVEDB] {cve_id}"
        if vendor and product:
            title += f" — {vendor}/{product}"

        # Tags
        tags = ["shodan", "cvedb", severity]
        if is_kev:
            tags.append("kev")
        if ransomware and ransomware.lower() != "unknown":
            tags.append("ransomware")
        if vendor:
            tags.append(vendor.lower())
        if epss >= 0.5:
            tags.append("high_epss")

        # Summary
        epss_pct = f"{epss * 100:.1f}%"
        summary = f"CVSS: {cvss_v3} | EPSS: {epss_pct} (top {ranking_epss * 100:.0f}%)"
        if is_kev:
            summary += " | KEV: Yes"
        if ransomware and ransomware.lower() != "unknown":
            summary += f" | Ransomware: {ransomware}"
        if vendor and product:
            summary += f" | {vendor}/{product}"

        # Description
        description = summary_text
        if propose_action:
            description += f"\n\nRecommended Action: {propose_action}"
        if references:
            description += "\n\nReferences:\n" + "\n".join(f"- {r}" for r in references[:5])

        # Source URL
        source_url = f"https://www.shodan.io/cve/{cve_id}" if cve_id else ""

        # Affected products
        affected = []
        if vendor and product:
            affected.append(f"{vendor}/{product}")

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
            "source_name": "Shodan CVEDB",
            "source_url": source_url,
            "source_reliability": self.SOURCE_RELIABILITY,
            "source_ref": cve_id,
            "feed_type": "vulnerability",
            "asset_type": "cve",
            "tlp": "TLP:CLEAR",
            "tags": tags[:15],
            "geo": [],
            "industries": [],
            "cve_ids": [cve_id],
            "affected_products": affected,
            "related_ioc_count": len(references),
            "is_kev": is_kev,
            "exploit_available": epss >= 0.5 or is_kev,
            "exploitability_score": round(epss * 10, 1) if epss else None,
            "source_hash": self.generate_hash("shodan_cvedb", cve_id),
        }

    def _normalize_host(self, raw: dict) -> dict | None:
        """Normalize a Shodan host/service entry (for future use with paid plans)."""
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

        cve_ids = [k for k in vulns.keys() if k.startswith("CVE-")][:20] if isinstance(vulns, dict) else []
        vuln_count = len(cve_ids)

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

        description = f"Exposed service on {ip}:{port}/{transport}"
        if product:
            description += f"\nProduct: {product}"
        if version:
            description += f" v{version}"
        if org:
            description += f"\nOrganization: {org}"
        if cve_ids:
            description += f"\nVulnerabilities: {', '.join(cve_ids[:10])}"

        return {
            "id": uuid.uuid4(),
            "title": title[:500],
            "summary": summary[:500],
            "description": description[:2000],
            "published_at": self.now_utc(),
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
