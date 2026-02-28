"""On-demand IOC enrichment — VirusTotal + Shodan lookups."""

from __future__ import annotations

import hashlib
import base64
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

VT_BASE = "https://www.virustotal.com/api/v3"
INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_API_URL = "https://api.shodan.io"

TIMEOUT = 15


async def enrich_ioc(value: str, ioc_type: str) -> dict[str, Any]:
    """Enrich a single IOC with VirusTotal and Shodan data.

    Returns a dict with keys: virustotal, shodan, errors
    """
    result: dict[str, Any] = {"virustotal": None, "shodan": None, "errors": []}

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        # ── VirusTotal ───────────────────────────────────
        if settings.virustotal_api_key:
            vt = await _vt_lookup(client, value, ioc_type)
            if isinstance(vt, str):
                result["errors"].append(vt)
            else:
                result["virustotal"] = vt

        # ── Shodan ───────────────────────────────────────
        if ioc_type == "ip":
            shodan = await _shodan_lookup(client, value)
            if isinstance(shodan, str):
                result["errors"].append(shodan)
            else:
                result["shodan"] = shodan
        elif ioc_type == "domain":
            # InternetDB doesn't support domains; use Shodan DNS if key available
            if settings.shodan_api_key:
                shodan = await _shodan_dns_lookup(client, value)
                if isinstance(shodan, str):
                    result["errors"].append(shodan)
                else:
                    result["shodan"] = shodan

    return result


# ── VirusTotal helpers ───────────────────────────────────

async def _vt_lookup(client: httpx.AsyncClient, value: str, ioc_type: str) -> dict | str:
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        if ioc_type == "ip":
            resp = await client.get(f"{VT_BASE}/ip_addresses/{value}", headers=headers)
        elif ioc_type == "domain":
            resp = await client.get(f"{VT_BASE}/domains/{value}", headers=headers)
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
        elif ioc_type in ("hash", "hash_md5", "hash_sha1", "hash_sha256"):
            resp = await client.get(f"{VT_BASE}/files/{value}", headers=headers)
        else:
            return "VT: unsupported IOC type"

        if resp.status_code == 429:
            return "VT: rate limited — try again later"
        if resp.status_code == 401:
            return "VT: invalid API key"
        if resp.status_code == 404:
            return {"found": False, "message": "Not found in VirusTotal"}
        if resp.status_code != 200:
            return f"VT: HTTP {resp.status_code}"

        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})

        # Build a clean summary
        summary: dict[str, Any] = {"found": True, "id": data.get("id")}

        if ioc_type == "ip":
            stats = attrs.get("last_analysis_stats", {})
            summary.update({
                "reputation": attrs.get("reputation", 0),
                "country": attrs.get("country", ""),
                "as_owner": attrs.get("as_owner", ""),
                "asn": attrs.get("asn"),
                "network": attrs.get("network", ""),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "tags": attrs.get("tags", []),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "whois": (attrs.get("whois") or "")[:500],
            })
        elif ioc_type == "domain":
            stats = attrs.get("last_analysis_stats", {})
            summary.update({
                "reputation": attrs.get("reputation", 0),
                "registrar": attrs.get("registrar", ""),
                "creation_date": attrs.get("creation_date"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "categories": attrs.get("categories", {}),
                "tags": attrs.get("tags", []),
                "last_analysis_date": attrs.get("last_analysis_date"),
            })
        elif ioc_type == "url":
            stats = attrs.get("last_analysis_stats", {})
            summary.update({
                "reputation": attrs.get("reputation", 0),
                "url": attrs.get("url", value),
                "final_url": attrs.get("last_final_url", ""),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "title": attrs.get("title", ""),
                "tags": attrs.get("tags", []),
                "last_analysis_date": attrs.get("last_analysis_date"),
            })
        else:  # file hash
            stats = attrs.get("last_analysis_stats", {})
            names = attrs.get("names", [])
            summary.update({
                "name": names[0] if names else "",
                "type_description": attrs.get("type_description", ""),
                "size": attrs.get("size"),
                "sha256": attrs.get("sha256", ""),
                "md5": attrs.get("md5", ""),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "popular_threat_classification": attrs.get("popular_threat_classification", {}),
                "tags": attrs.get("tags", []),
                "first_submission_date": attrs.get("first_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
            })

        return summary

    except httpx.TimeoutException:
        return "VT: request timed out"
    except Exception as e:
        logger.error("vt_enrich_error", value=value, error=str(e))
        return f"VT: {str(e)}"


# ── Shodan helpers ───────────────────────────────────────

async def _shodan_lookup(client: httpx.AsyncClient, ip: str) -> dict | str:
    """InternetDB (free, no key) + Shodan API (if key available)."""
    result: dict[str, Any] = {"found": False}

    # 1. InternetDB — always free
    try:
        resp = await client.get(f"{INTERNETDB_URL}/{ip}")
        if resp.status_code == 200:
            data = resp.json()
            result.update({
                "found": True,
                "source": "internetdb",
                "hostnames": data.get("hostnames", []),
                "ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
            })
        elif resp.status_code == 404:
            result["internetdb_note"] = "IP not found in InternetDB"
    except Exception as e:
        logger.debug("internetdb_error", ip=ip, error=str(e))

    # 2. Shodan API — if key available
    if settings.shodan_api_key:
        try:
            resp = await client.get(
                f"{SHODAN_API_URL}/shodan/host/{ip}",
                params={"key": settings.shodan_api_key},
            )
            if resp.status_code == 200:
                data = resp.json()
                result.update({
                    "found": True,
                    "source": "shodan_api",
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "os": data.get("os"),
                    "country_name": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "last_update": data.get("last_update", ""),
                    "open_ports": data.get("ports", []),
                    "shodan_vulns": data.get("vulns", []),
                    "services_count": len(data.get("data", [])),
                })
            elif resp.status_code == 404:
                result.setdefault("shodan_api_note", "IP not found in Shodan")
            elif resp.status_code == 401:
                result["shodan_api_note"] = "Invalid Shodan API key"
        except Exception as e:
            logger.debug("shodan_api_error", ip=ip, error=str(e))

    return result


async def _shodan_dns_lookup(client: httpx.AsyncClient, domain: str) -> dict | str:
    """Shodan DNS resolve for a domain."""
    try:
        resp = await client.get(
            f"{SHODAN_API_URL}/dns/resolve",
            params={"hostnames": domain, "key": settings.shodan_api_key},
        )
        if resp.status_code != 200:
            return f"Shodan DNS: HTTP {resp.status_code}"
        data = resp.json()
        ip = data.get(domain)
        if not ip:
            return {"found": False, "message": "Domain could not be resolved"}
        # Now look up the resolved IP
        result = await _shodan_lookup(client, ip)
        if isinstance(result, dict):
            result["resolved_ip"] = ip
        return result
    except Exception as e:
        return f"Shodan DNS: {str(e)}"
