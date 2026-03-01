"""Live Internet Lookup — real-time IOC intelligence from external sources.

When local search yields zero/few results, this service queries
external threat intelligence APIs based on IOC type:

  CVE      → NVD (full CVE details + CVSS + references) + CISA KEV check
  IP       → AbuseIPDB (abuse confidence, reports) + VirusTotal + Shodan
  Domain   → VirusTotal (reputation + detection) + Shodan (ports, vulns)
  Hash     → VirusTotal (file analysis + detections)
  URL      → VirusTotal (URL scan) + URLhaus (malware check)
  Keyword  → NVD keyword search + OTX pulse search + DuckDuckGo web intel

Results are returned immediately, optionally AI-summarized,
and can be saved into the local DB for future searches.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redis import cache_key, get_cached, set_cached
from app.services.search import detect_ioc_type

logger = get_logger(__name__)
settings = get_settings()

TIMEOUT = 15


async def live_lookup(query: str) -> dict[str, Any]:
    """Orchestrate live internet lookup based on auto-detected IOC type.

    Returns structured results from multiple external sources.
    """
    ck = cache_key("live_lookup", query.strip().lower())
    cached = await get_cached(ck)
    if cached:
        return cached

    q = query.strip()
    detected_type = detect_ioc_type(q)
    source_tag = detected_type or "keyword"

    result: dict[str, Any] = {
        "query": q,
        "detected_type": detected_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sources_queried": [],
        "results": [],
        "ai_summary": None,
        "errors": [],
    }

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        tasks: list[tuple[str, Any]] = []

        if detected_type == "cve":
            tasks.append(("NVD", _lookup_nvd_cve(client, q)))
            tasks.append(("CISA KEV", _lookup_kev(client, q)))
            tasks.append(("Web Search", _lookup_web(client, q)))

        elif detected_type == "ip":
            tasks.append(("AbuseIPDB", _lookup_abuseipdb(client, q)))
            if settings.virustotal_api_key:
                tasks.append(("VirusTotal", _lookup_vt_ip(client, q)))
            tasks.append(("Shodan", _lookup_shodan_ip(client, q)))

        elif detected_type == "domain":
            if settings.virustotal_api_key:
                tasks.append(("VirusTotal", _lookup_vt_domain(client, q)))
            if settings.shodan_api_key:
                tasks.append(("Shodan", _lookup_shodan_domain(client, q)))
            tasks.append(("Web Search", _lookup_web(client, q)))

        elif detected_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            if settings.virustotal_api_key:
                tasks.append(("VirusTotal", _lookup_vt_hash(client, q)))

        elif detected_type == "url":
            if settings.virustotal_api_key:
                tasks.append(("VirusTotal", _lookup_vt_url(client, q)))
            tasks.append(("URLhaus", _lookup_urlhaus(client, q)))

        elif detected_type == "email":
            tasks.append(("Web Search", _lookup_web(client, f"{q} threat intelligence")))

        else:
            # Keyword/generic search
            tasks.append(("NVD", _lookup_nvd_keyword(client, q)))
            if settings.otx_api_key:
                tasks.append(("OTX", _lookup_otx(client, q)))
            tasks.append(("Web Search", _lookup_web(client, q)))

        # Execute all in parallel
        coro_list = [t[1] for t in tasks]
        source_names = [t[0] for t in tasks]
        gathered = await asyncio.gather(*coro_list, return_exceptions=True)

        for name, out in zip(source_names, gathered):
            result["sources_queried"].append(name)
            if isinstance(out, Exception):
                result["errors"].append(f"{name}: {str(out)}")
            elif isinstance(out, str):
                result["errors"].append(out)
            elif isinstance(out, list):
                result["results"].extend(out)
            elif isinstance(out, dict):
                result["results"].append(out)

    # AI summary if results found and AI available
    if result["results"] and settings.ai_api_key:
        try:
            result["ai_summary"] = await _ai_summarize(q, source_tag, result["results"])
        except Exception as e:
            logger.debug("live_lookup_ai_error", error=str(e))

    # Cache for 10 minutes
    await set_cached(ck, result, ttl=600)
    logger.info("live_lookup_complete", query=q[:80], type=source_tag,
                sources=len(result["sources_queried"]), results=len(result["results"]))
    return result


# ─── NVD ─────────────────────────────────────────────────

async def _lookup_nvd_cve(client: httpx.AsyncClient, cve_id: str) -> list[dict]:
    """Fetch full CVE details from NVD."""
    headers: dict[str, str] = {"User-Agent": "IntelWatch/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    resp = await client.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id.upper()},
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cid = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score, cvss_sev, exploit_score = None, None, None
        for vk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ml = metrics.get(vk, [])
            if ml:
                cd = ml[0].get("cvssData", {})
                cvss_score = cd.get("baseScore")
                cvss_sev = cd.get("baseSeverity", "").lower()
                exploit_score = ml[0].get("exploitabilityScore")
                break

        refs = cve.get("references", [])
        ref_urls = [r.get("url", "") for r in refs[:8]]
        has_exploit = any("exploit" in " ".join(r.get("tags", [])).lower() for r in refs)

        products = []
        for cfg in cve.get("configurations", [])[:3]:
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", [])[:5]:
                    parts = m.get("criteria", "").split(":")
                    if len(parts) >= 5:
                        products.append(f"{parts[3]}:{parts[4]}")

        severity = cvss_sev if cvss_sev in ("critical", "high", "medium", "low") else "unknown"
        risk = int((cvss_score or 0) * 10)

        results.append({
            "source": "NVD",
            "type": "cve",
            "title": f"{cid}: {desc[:150]}",
            "description": desc[:1000],
            "severity": severity,
            "risk_score": min(risk, 100),
            "confidence": 90,
            "cve_id": cid,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_sev,
            "exploitability_score": exploit_score,
            "exploit_available": has_exploit,
            "affected_products": list(set(products))[:10],
            "references": ref_urls,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        })

    return results


async def _lookup_nvd_keyword(client: httpx.AsyncClient, keyword: str) -> list[dict]:
    """Search NVD by keyword."""
    headers: dict[str, str] = {"User-Agent": "IntelWatch/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    kw = _clean_keywords(keyword)
    if not kw:
        return []

    try:
        resp = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": kw, "resultsPerPage": 5},
            headers=headers,
        )
        resp.raise_for_status()
    except Exception:
        return []

    results = []
    for vuln in resp.json().get("vulnerabilities", [])[:5]:
        cve = vuln.get("cve", {})
        cid = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score, cvss_sev = None, None
        for vk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ml = metrics.get(vk, [])
            if ml:
                cd = ml[0].get("cvssData", {})
                cvss_score = cd.get("baseScore")
                cvss_sev = cd.get("baseSeverity", "").lower()
                break

        severity = cvss_sev if cvss_sev in ("critical", "high", "medium", "low") else "unknown"

        results.append({
            "source": "NVD",
            "type": "cve",
            "title": f"{cid}: {desc[:150]}",
            "description": desc[:500],
            "severity": severity,
            "risk_score": int((cvss_score or 0) * 10),
            "confidence": 85,
            "cve_id": cid,
            "cvss_score": cvss_score,
            "published": cve.get("published", ""),
        })

    return results


# ─── CISA KEV ────────────────────────────────────────────

async def _lookup_kev(client: httpx.AsyncClient, cve_id: str) -> dict | str:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog."""
    try:
        resp = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"User-Agent": "IntelWatch/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID", "").upper() == cve_id.upper():
                return {
                    "source": "CISA KEV",
                    "type": "kev",
                    "title": f"[KEV] {cve_id}: {vuln.get('vendorProject', '')} {vuln.get('product', '')}",
                    "description": vuln.get("shortDescription", ""),
                    "severity": "critical",
                    "risk_score": 95,
                    "confidence": 99,
                    "cve_id": cve_id.upper(),
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "date_added": vuln.get("dateAdded", ""),
                    "due_date": vuln.get("dueDate", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": vuln.get("notes", ""),
                    "is_kev": True,
                }
        # Not in KEV
        return []
    except Exception as e:
        return f"KEV: {str(e)}"


# ─── AbuseIPDB ───────────────────────────────────────────

async def _lookup_abuseipdb(client: httpx.AsyncClient, ip: str) -> dict | str:
    """Check an IP against AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return "AbuseIPDB: no API key configured"

    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={
                "Key": settings.abuseipdb_api_key,
                "Accept": "application/json",
            },
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})

        abuse_score = d.get("abuseConfidenceScore", 0)
        severity = "critical" if abuse_score >= 80 else "high" if abuse_score >= 50 else "medium" if abuse_score >= 20 else "low"

        categories = d.get("reports", [])
        cat_names = set()
        for r in (categories if isinstance(categories, list) else [])[:20]:
            for c in (r.get("categories", []) if isinstance(r, dict) else []):
                cat_names.add(_abuseipdb_category(c))

        return {
            "source": "AbuseIPDB",
            "type": "ip_reputation",
            "title": f"AbuseIPDB: {ip} — Abuse Score {abuse_score}%",
            "description": (
                f"IP {ip} has an abuse confidence score of {abuse_score}%. "
                f"Reported {d.get('totalReports', 0)} times by {d.get('numDistinctUsers', 0)} users. "
                f"ISP: {d.get('isp', 'N/A')}. Country: {d.get('countryCode', 'N/A')}. "
                f"Usage: {d.get('usageType', 'N/A')}. Domain: {d.get('domain', 'N/A')}."
            ),
            "severity": severity,
            "risk_score": abuse_score,
            "confidence": 80,
            "abuse_score": abuse_score,
            "total_reports": d.get("totalReports", 0),
            "distinct_users": d.get("numDistinctUsers", 0),
            "isp": d.get("isp", ""),
            "country": d.get("countryCode", ""),
            "domain": d.get("domain", ""),
            "usage_type": d.get("usageType", ""),
            "is_whitelisted": d.get("isWhitelisted", False),
            "categories": list(cat_names),
            "last_reported": d.get("lastReportedAt", ""),
        }
    except Exception as e:
        return f"AbuseIPDB: {str(e)}"


def _abuseipdb_category(cat_id: int) -> str:
    """Map AbuseIPDB category IDs to names."""
    cats = {
        1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
        5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
        9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
        13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
        17: "Email Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
    }
    return cats.get(cat_id, f"Category-{cat_id}")


# ─── VirusTotal ──────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"


async def _vt_request(client: httpx.AsyncClient, url: str) -> dict | None:
    """Make a VT API request, return data or None."""
    resp = await client.get(url, headers={"x-apikey": settings.virustotal_api_key})
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        raise Exception("rate limited — try again later")
    resp.raise_for_status()
    return resp.json().get("data", {})


def _vt_detection_summary(attrs: dict) -> tuple[int, int, str]:
    """Extract malicious count, total engines, severity."""
    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0
    if mal > 10:
        sev = "critical"
    elif mal > 3:
        sev = "high"
    elif mal > 0:
        sev = "medium"
    else:
        sev = "low"
    return mal, total, sev


async def _lookup_vt_ip(client: httpx.AsyncClient, ip: str) -> dict | str:
    """VirusTotal IP lookup."""
    try:
        data = await _vt_request(client, f"{VT_BASE}/ip_addresses/{ip}")
        if not data:
            return []
        attrs = data.get("attributes", {})
        mal, total, sev = _vt_detection_summary(attrs)
        return {
            "source": "VirusTotal",
            "type": "ip_analysis",
            "title": f"VirusTotal: {ip} — {mal}/{total} detections",
            "description": (
                f"IP {ip} flagged by {mal} of {total} engines. "
                f"Reputation: {attrs.get('reputation', 0)}. "
                f"Country: {attrs.get('country', 'N/A')}. "
                f"AS: {attrs.get('as_owner', 'N/A')} (ASN {attrs.get('asn', 'N/A')})."
            ),
            "severity": sev,
            "risk_score": min(int(mal / max(total, 1) * 100), 100),
            "confidence": 85,
            "malicious": mal,
            "total_engines": total,
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "asn": attrs.get("asn"),
            "network": attrs.get("network", ""),
            "tags": attrs.get("tags", []),
        }
    except Exception as e:
        return f"VirusTotal: {str(e)}"


async def _lookup_vt_domain(client: httpx.AsyncClient, domain: str) -> dict | str:
    """VirusTotal domain lookup."""
    try:
        data = await _vt_request(client, f"{VT_BASE}/domains/{domain}")
        if not data:
            return []
        attrs = data.get("attributes", {})
        mal, total, sev = _vt_detection_summary(attrs)
        return {
            "source": "VirusTotal",
            "type": "domain_analysis",
            "title": f"VirusTotal: {domain} — {mal}/{total} detections",
            "description": (
                f"Domain {domain} flagged by {mal} of {total} engines. "
                f"Reputation: {attrs.get('reputation', 0)}. "
                f"Registrar: {attrs.get('registrar', 'N/A')}."
            ),
            "severity": sev,
            "risk_score": min(int(mal / max(total, 1) * 100), 100),
            "confidence": 85,
            "malicious": mal,
            "total_engines": total,
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar", ""),
            "categories": attrs.get("categories", {}),
            "tags": attrs.get("tags", []),
        }
    except Exception as e:
        return f"VirusTotal: {str(e)}"


async def _lookup_vt_hash(client: httpx.AsyncClient, file_hash: str) -> dict | str:
    """VirusTotal file hash lookup."""
    try:
        data = await _vt_request(client, f"{VT_BASE}/files/{file_hash}")
        if not data:
            return {"source": "VirusTotal", "type": "hash_analysis",
                    "title": f"VirusTotal: {file_hash[:16]}… — Not found",
                    "description": "This hash was not found in VirusTotal's database.",
                    "severity": "info", "risk_score": 0, "confidence": 50}
        attrs = data.get("attributes", {})
        mal, total, sev = _vt_detection_summary(attrs)
        names = attrs.get("names", [])
        return {
            "source": "VirusTotal",
            "type": "hash_analysis",
            "title": f"VirusTotal: {(names[0] if names else file_hash[:24])} — {mal}/{total} detections",
            "description": (
                f"File {names[0] if names else 'unknown'} ({attrs.get('type_description', 'unknown type')}). "
                f"Size: {attrs.get('size', 0)} bytes. "
                f"Detected by {mal} of {total} engines."
            ),
            "severity": sev,
            "risk_score": min(int(mal / max(total, 1) * 100), 100),
            "confidence": 90,
            "malicious": mal,
            "total_engines": total,
            "file_name": names[0] if names else "",
            "file_type": attrs.get("type_description", ""),
            "file_size": attrs.get("size"),
            "sha256": attrs.get("sha256", ""),
            "md5": attrs.get("md5", ""),
            "tags": attrs.get("tags", []),
            "threat_classification": attrs.get("popular_threat_classification", {}),
        }
    except Exception as e:
        return f"VirusTotal: {str(e)}"


async def _lookup_vt_url(client: httpx.AsyncClient, url: str) -> dict | str:
    """VirusTotal URL lookup."""
    import base64
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = await _vt_request(client, f"{VT_BASE}/urls/{url_id}")
        if not data:
            return {"source": "VirusTotal", "type": "url_analysis",
                    "title": "VirusTotal: URL — Not found",
                    "description": "This URL was not found in VirusTotal.",
                    "severity": "info", "risk_score": 0, "confidence": 50}
        attrs = data.get("attributes", {})
        mal, total, sev = _vt_detection_summary(attrs)
        return {
            "source": "VirusTotal",
            "type": "url_analysis",
            "title": f"VirusTotal: {url[:60]} — {mal}/{total} detections",
            "description": (
                f"URL flagged by {mal} of {total} engines. "
                f"Final URL: {attrs.get('last_final_url', url)[:120]}. "
                f"Title: {attrs.get('title', 'N/A')}."
            ),
            "severity": sev,
            "risk_score": min(int(mal / max(total, 1) * 100), 100),
            "confidence": 80,
            "malicious": mal,
            "total_engines": total,
            "final_url": attrs.get("last_final_url", ""),
            "page_title": attrs.get("title", ""),
            "tags": attrs.get("tags", []),
        }
    except Exception as e:
        return f"VirusTotal: {str(e)}"


# ─── Shodan ──────────────────────────────────────────────

async def _lookup_shodan_ip(client: httpx.AsyncClient, ip: str) -> dict | str:
    """Shodan IP lookup (InternetDB free + API if available)."""
    result: dict[str, Any] = {}

    # InternetDB (free)
    try:
        resp = await client.get(f"https://internetdb.shodan.io/{ip}")
        if resp.status_code == 200:
            d = resp.json()
            ports = d.get("ports", [])
            vulns = d.get("vulns", [])
            sev = "critical" if len(vulns) > 5 else "high" if vulns else "medium" if len(ports) > 10 else "low"
            result = {
                "source": "Shodan",
                "type": "ip_infrastructure",
                "title": f"Shodan: {ip} — {len(ports)} ports, {len(vulns)} vulns",
                "description": (
                    f"Open ports: {', '.join(str(p) for p in ports[:15])}. "
                    f"Vulnerabilities: {', '.join(vulns[:10])}. "
                    f"Hostnames: {', '.join(d.get('hostnames', [])[:5])}."
                ),
                "severity": sev,
                "risk_score": min(len(vulns) * 15 + len(ports) * 3, 100),
                "confidence": 75,
                "ports": ports,
                "vulns": vulns,
                "hostnames": d.get("hostnames", []),
                "cpes": d.get("cpes", []),
                "tags": d.get("tags", []),
            }
    except Exception as e:
        return f"Shodan: {str(e)}"

    # Shodan API (if key)
    if settings.shodan_api_key:
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": settings.shodan_api_key},
            )
            if resp.status_code == 200:
                d = resp.json()
                result.update({
                    "org": d.get("org", ""),
                    "isp": d.get("isp", ""),
                    "os": d.get("os"),
                    "country": d.get("country_name", ""),
                    "city": d.get("city", ""),
                    "services_count": len(d.get("data", [])),
                })
        except Exception:
            pass  # InternetDB result is still valid

    return result if result else []


async def _lookup_shodan_domain(client: httpx.AsyncClient, domain: str) -> dict | str:
    """Shodan domain DNS resolve + IP lookup."""
    try:
        resp = await client.get(
            "https://api.shodan.io/dns/resolve",
            params={"hostnames": domain, "key": settings.shodan_api_key},
        )
        if resp.status_code != 200:
            return f"Shodan DNS: HTTP {resp.status_code}"
        ip = resp.json().get(domain)
        if not ip:
            return []
        r = await _lookup_shodan_ip(client, ip)
        if isinstance(r, dict):
            r["resolved_ip"] = ip
            r["title"] = f"Shodan: {domain} ({ip}) — {r.get('title', '').split('—')[-1].strip()}"
        return r
    except Exception as e:
        return f"Shodan: {str(e)}"


# ─── URLhaus ─────────────────────────────────────────────

async def _lookup_urlhaus(client: httpx.AsyncClient, url: str) -> dict | str:
    """Check a URL against URLhaus."""
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"User-Agent": "IntelWatch/1.0"},
        )
        resp.raise_for_status()
        d = resp.json()

        if d.get("query_status") != "ok" or not d.get("id"):
            return []

        threat = d.get("threat", "malware_download")
        tags = d.get("tags") or []

        return {
            "source": "URLhaus",
            "type": "url_malware",
            "title": f"URLhaus: {url[:60]} — {threat}",
            "description": (
                f"URL classified as {threat}. Status: {d.get('url_status', 'N/A')}. "
                f"Added: {d.get('date_added', 'N/A')}. Reporter: {d.get('reporter', 'N/A')}. "
                f"Tags: {', '.join(tags[:5])}."
            ),
            "severity": "high",
            "risk_score": 80,
            "confidence": 85,
            "threat_type": threat,
            "url_status": d.get("url_status", ""),
            "date_added": d.get("date_added", ""),
            "tags": tags,
            "payloads": [
                {
                    "filename": p.get("filename", ""),
                    "file_type": p.get("file_type", ""),
                    "signature": p.get("signature"),
                    "virustotal_pct": p.get("virustotal", {}).get("percent"),
                }
                for p in (d.get("payloads") or [])[:5]
            ],
        }
    except Exception as e:
        return f"URLhaus: {str(e)}"


# ─── OTX ─────────────────────────────────────────────────

async def _lookup_otx(client: httpx.AsyncClient, keyword: str) -> list[dict]:
    """Search OTX pulse database."""
    kw = _clean_keywords(keyword)
    if not kw:
        return []

    try:
        resp = await client.get(
            "https://otx.alienvault.com/api/v1/search/pulses",
            params={"q": kw, "limit": 5},
            headers={
                "X-OTX-API-KEY": settings.otx_api_key,
                "User-Agent": "IntelWatch/1.0",
            },
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    results = []
    for pulse in data.get("results", [])[:5]:
        indicators = pulse.get("indicators", [])
        ioc_sample = [f"{i.get('type')}: {i.get('indicator')}" for i in indicators[:5]]

        ioc_count = len(indicators)
        sev = "critical" if ioc_count > 100 else "high" if ioc_count > 30 else "medium" if ioc_count > 5 else "low"

        results.append({
            "source": "OTX",
            "type": "threat_pulse",
            "title": f"[OTX] {pulse.get('name', '')}",
            "description": (pulse.get("description") or f"Threat pulse with {ioc_count} indicators")[:500],
            "severity": sev,
            "risk_score": min(ioc_count * 2, 90),
            "confidence": 65,
            "ioc_count": ioc_count,
            "iocs_sample": ioc_sample,
            "tags": pulse.get("tags", [])[:10],
            "adversary": pulse.get("adversary", ""),
            "targeted_countries": pulse.get("targeted_countries", []),
            "created": pulse.get("created", ""),
        })

    return results


# ─── Web Search ──────────────────────────────────────────

async def _lookup_web(client: httpx.AsyncClient, query: str) -> list[dict]:
    """Search DuckDuckGo for recent threat intelligence articles."""
    kw = _clean_keywords(query)
    if not kw:
        return []

    search_q = f"{kw} cybersecurity threat intelligence 2026"

    try:
        resp = await client.get(
            "https://html.duckduckgo.com/html/",
            params={"q": search_q},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        )
        resp.raise_for_status()
    except Exception:
        return []

    html = resp.text
    title_pattern = re.compile(r'class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>', re.DOTALL)
    snippet_pattern = re.compile(r'class="result__snippet"[^>]*>(.*?)</(?:a|div|span)>', re.DOTALL)

    titles = title_pattern.findall(html)
    snippets = snippet_pattern.findall(html)

    results = []
    for i, (url, title) in enumerate(titles[:6]):
        snippet = snippets[i] if i < len(snippets) else ""
        clean_title = re.sub(r"<[^>]+>", "", title).strip()
        clean_snippet = re.sub(r"<[^>]+>", "", snippet).strip()

        if not clean_title or not url:
            continue

        # Resolve DuckDuckGo redirect URLs
        actual_url = url
        if "duckduckgo.com" in url:
            url_match = re.search(r"uddg=([^&]+)", url)
            if url_match:
                from urllib.parse import unquote
                actual_url = unquote(url_match.group(1))

        results.append({
            "source": "Web Search",
            "type": "web_article",
            "title": clean_title,
            "description": clean_snippet[:400],
            "severity": "info",
            "risk_score": 0,
            "confidence": 40,
            "url": actual_url,
        })

    return results


# ─── AI Summary ──────────────────────────────────────────

async def _ai_summarize(query: str, ioc_type: str, results: list[dict]) -> str | None:
    """Use AI to synthesize a concise summary of live lookup findings."""
    if not settings.ai_api_key:
        return None

    # Build context from results
    context_parts = []
    for r in results[:10]:
        line = f"[{r.get('source', '?')}] {r.get('title', '')}"
        if r.get("description"):
            line += f"\n  {r['description'][:200]}"
        context_parts.append(line)

    context = "\n\n".join(context_parts)

    system = (
        "You are a concise threat intelligence analyst. Given live lookup results for an IOC, "
        "write a 2-4 sentence executive summary: what is this IOC, is it malicious, what's the "
        "key risk, and what action should be taken. Be direct and factual."
    )
    user_msg = f"IOC: {query} (type: {ioc_type})\n\nLive lookup results:\n{context}"

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            resp = await c.post(
                settings.ai_api_url,
                headers={
                    "Authorization": f"Bearer {settings.ai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": settings.ai_model if hasattr(settings, "ai_model") and settings.ai_model else "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 250,
                },
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        logger.debug("ai_summary_error", error=str(e))
        return None


# ─── Helpers ─────────────────────────────────────────────

def _clean_keywords(text: str) -> str:
    """Extract meaningful keywords from a query string."""
    stop = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "can", "of", "in", "to", "for", "with",
        "on", "at", "from", "by", "about", "as", "into", "through",
    }
    words = re.findall(r"[A-Za-z0-9][\w.-]*", text)
    kw = [w for w in words if w.lower() not in stop and len(w) > 1]
    return " ".join(kw[:8])
