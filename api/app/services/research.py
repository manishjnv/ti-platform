"""Research service — gathers live internet intelligence for AI report generation.

Sources:
  - Local OpenSearch index (already-ingested intel items)
  - NVD API (CVE details, CVSS scores, references)
  - DuckDuckGo web search (recent news, advisories, PoC info)
  - OTX API (threat indicators, pulses)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.opensearch import search_intel

logger = get_logger(__name__)
settings = get_settings()


async def gather_research(topic: str, *, max_results: int = 10) -> dict:
    """Orchestrate research from all sources for a given topic.

    Returns a structured dict with research findings from each source.
    """
    results: dict = {
        "topic": topic,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "local_intel": [],
        "nvd_cves": [],
        "web_results": [],
        "otx_pulses": [],
    }

    # Run all research in parallel-ish (gather tasks)
    import asyncio

    tasks = [
        _search_local_intel(topic, max_results),
        _search_nvd(topic),
        _search_web(topic),
        _search_otx(topic),
    ]

    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    if not isinstance(gathered[0], Exception):
        results["local_intel"] = gathered[0]
    else:
        logger.warning("research_local_error", error=str(gathered[0]))

    if not isinstance(gathered[1], Exception):
        results["nvd_cves"] = gathered[1]
    else:
        logger.warning("research_nvd_error", error=str(gathered[1]))

    if not isinstance(gathered[2], Exception):
        results["web_results"] = gathered[2]
    else:
        logger.warning("research_web_error", error=str(gathered[2]))

    if not isinstance(gathered[3], Exception):
        results["otx_pulses"] = gathered[3]
    else:
        logger.warning("research_otx_error", error=str(gathered[3]))

    total = sum(len(v) for v in results.values() if isinstance(v, list))
    logger.info("research_complete", topic=topic[:80], total_items=total)

    return results


async def _search_local_intel(topic: str, max_results: int = 10) -> list[dict]:
    """Search local OpenSearch index for related intel items."""
    query = {
        "query": {
            "multi_match": {
                "query": topic,
                "fields": ["title^3", "description^2", "cve_ids", "tags", "source_feed"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        },
        "sort": [{"_score": "desc"}, {"published_at": "desc"}],
    }

    try:
        result = search_intel(query, size=max_results)
        hits = result.get("hits", {}).get("hits", [])
        items = []
        for hit in hits:
            src = hit["_source"]
            items.append({
                "title": src.get("title", ""),
                "description": (src.get("description") or "")[:300],
                "severity": src.get("severity", ""),
                "source": src.get("source_feed", ""),
                "cve_ids": src.get("cve_ids", []),
                "published": src.get("published_at", ""),
                "score": hit.get("_score", 0),
            })
        return items
    except Exception as e:
        logger.warning("research_opensearch_error", error=str(e))
        return []


async def _search_nvd(topic: str) -> list[dict]:
    """Search NVD for CVE data related to the topic."""
    # Extract CVE IDs from the topic if present
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    cve_ids = cve_pattern.findall(topic)

    results = []

    async with httpx.AsyncClient(timeout=15) as client:
        headers = {"User-Agent": "IntelWatch/1.0"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        # If specific CVE IDs found, fetch details for each
        if cve_ids:
            for cve_id in cve_ids[:5]:  # Limit to 5 CVEs
                try:
                    resp = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"cveId": cve_id.upper()},
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for vuln in data.get("vulnerabilities", []):
                        results.append(_parse_nvd_cve(vuln))
                except Exception as e:
                    logger.debug("nvd_cve_fetch_error", cve=cve_id, error=str(e))
        else:
            # Keyword search — use first few meaningful words
            keywords = _extract_search_keywords(topic)
            if keywords:
                try:
                    resp = await client.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": keywords, "resultsPerPage": 5},
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    for vuln in data.get("vulnerabilities", [])[:5]:
                        results.append(_parse_nvd_cve(vuln))
                except Exception as e:
                    logger.debug("nvd_keyword_search_error", error=str(e))

    return results


def _parse_nvd_cve(vuln: dict) -> dict:
    """Parse a single NVD CVE vulnerability entry."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # Description
    desc_list = cve.get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

    # CVSS score
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity", "")
            break

    # Exploitability
    exploit_score = None
    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            exploit_score = metric_list[0].get("exploitabilityScore")
            break

    # References
    refs = cve.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:5]]
    has_exploit_ref = any(
        "exploit" in (r.get("url", "") + " ".join(r.get("tags", []))).lower()
        for r in refs
    )

    # Affected configurations (CPE)
    configs = cve.get("configurations", [])
    affected_products = []
    for config in configs[:3]:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", [])[:5]:
                cpe = match.get("criteria", "")
                if cpe:
                    # Extract vendor:product from CPE
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        affected_products.append(f"{parts[3]}:{parts[4]}")

    return {
        "cve_id": cve_id,
        "description": desc[:500],
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "exploitability_score": exploit_score,
        "has_known_exploit": has_exploit_ref,
        "affected_products": list(set(affected_products))[:10],
        "references": ref_urls,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
    }


async def _search_web(topic: str) -> list[dict]:
    """Search the web via DuckDuckGo HTML for recent articles about the topic."""
    keywords = _extract_search_keywords(topic)
    if not keywords:
        return []

    query = f"{keywords} cybersecurity threat advisory 2026"

    results = []
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
        try:
            # Use DuckDuckGo HTML search
            resp = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                },
            )
            resp.raise_for_status()
            html = resp.text

            # Simple regex-based extraction from DuckDuckGo HTML results
            # Each result is in <a class="result__a" href="...">title</a>
            # with <a class="result__snippet">snippet</a>
            title_pattern = re.compile(
                r'class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
                re.DOTALL,
            )
            snippet_pattern = re.compile(
                r'class="result__snippet"[^>]*>(.*?)</(?:a|div|span)>',
                re.DOTALL,
            )

            titles = title_pattern.findall(html)
            snippets = snippet_pattern.findall(html)

            for i, (url, title) in enumerate(titles[:8]):
                snippet = snippets[i] if i < len(snippets) else ""
                # Clean HTML tags from title and snippet
                clean_title = re.sub(r"<[^>]+>", "", title).strip()
                clean_snippet = re.sub(r"<[^>]+>", "", snippet).strip()

                if clean_title and url:
                    # DuckDuckGo wraps URLs — extract actual URL
                    actual_url = url
                    if "duckduckgo.com" in url:
                        url_match = re.search(r"uddg=([^&]+)", url)
                        if url_match:
                            from urllib.parse import unquote
                            actual_url = unquote(url_match.group(1))

                    results.append({
                        "title": clean_title,
                        "snippet": clean_snippet[:300],
                        "url": actual_url,
                    })

        except Exception as e:
            logger.warning("research_web_search_error", error=str(e))

    return results


async def _search_otx(topic: str) -> list[dict]:
    """Search OTX for threat pulses related to the topic."""
    if not settings.otx_api_key:
        return []

    keywords = _extract_search_keywords(topic)
    if not keywords:
        return []

    results = []
    async with httpx.AsyncClient(timeout=12) as client:
        try:
            resp = await client.get(
                "https://otx.alienvault.com/api/v1/search/pulses",
                params={"q": keywords, "limit": 5},
                headers={
                    "X-OTX-API-KEY": settings.otx_api_key,
                    "User-Agent": "IntelWatch/1.0",
                },
            )
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", [])[:5]:
                indicators = pulse.get("indicators", [])
                ioc_summary = []
                for ind in indicators[:10]:
                    ioc_summary.append(f"{ind.get('type', '')}: {ind.get('indicator', '')}")

                results.append({
                    "title": pulse.get("name", ""),
                    "description": (pulse.get("description") or "")[:300],
                    "created": pulse.get("created", ""),
                    "tags": pulse.get("tags", [])[:10],
                    "ioc_count": len(indicators),
                    "iocs_sample": ioc_summary[:5],
                    "adversary": pulse.get("adversary") or "",
                    "targeted_countries": pulse.get("targeted_countries", []),
                })
        except Exception as e:
            logger.warning("research_otx_error", error=str(e))

    return results


def _extract_search_keywords(topic: str) -> str:
    """Extract meaningful keywords from a topic string for search queries."""
    # Remove common filler words
    stop_words = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "can", "shall", "of", "in", "to", "for",
        "with", "on", "at", "from", "by", "about", "as", "into", "through",
        "during", "before", "after", "above", "below", "between", "report",
        "summary", "overview", "analysis", "assessment", "intelligence",
    }
    words = re.findall(r"[A-Za-z0-9][\w.-]*", topic)
    keywords = [w for w in words if w.lower() not in stop_words and len(w) > 1]
    return " ".join(keywords[:8])


def format_research_context(research: dict) -> str:
    """Format research results into a text context block for AI prompting."""
    parts = []

    # Local intel items
    local = research.get("local_intel", [])
    if local:
        parts.append("=== LOCAL INTELLIGENCE DATABASE ===")
        for item in local[:8]:
            line = f"- [{item['severity'].upper()}] {item['title']}"
            if item.get("cve_ids"):
                line += f" (CVEs: {', '.join(item['cve_ids'][:3])})"
            if item.get("description"):
                line += f"\n  {item['description'][:200]}"
            parts.append(line)

    # NVD CVE data
    cves = research.get("nvd_cves", [])
    if cves:
        parts.append("\n=== NVD VULNERABILITY DATA ===")
        for cve in cves:
            line = f"- {cve['cve_id']}: CVSS {cve.get('cvss_score', 'N/A')} ({cve.get('cvss_severity', 'N/A')})"
            if cve.get("exploitability_score"):
                line += f", Exploitability: {cve['exploitability_score']}/3.9"
            if cve.get("has_known_exploit"):
                line += " ⚠ KNOWN EXPLOIT EXISTS"
            parts.append(line)
            if cve.get("description"):
                parts.append(f"  Description: {cve['description'][:250]}")
            if cve.get("affected_products"):
                parts.append(f"  Affected: {', '.join(cve['affected_products'][:5])}")
            if cve.get("references"):
                parts.append(f"  References: {', '.join(cve['references'][:3])}")

    # Web search results
    web = research.get("web_results", [])
    if web:
        parts.append("\n=== RECENT WEB INTELLIGENCE ===")
        for item in web[:6]:
            parts.append(f"- {item['title']}")
            if item.get("snippet"):
                parts.append(f"  {item['snippet'][:200]}")
            if item.get("url"):
                parts.append(f"  Source: {item['url']}")

    # OTX threat pulses
    otx = research.get("otx_pulses", [])
    if otx:
        parts.append("\n=== OTX THREAT INTELLIGENCE ===")
        for pulse in otx:
            line = f"- {pulse['title']}"
            if pulse.get("adversary"):
                line += f" (Attributed to: {pulse['adversary']})"
            if pulse.get("ioc_count"):
                line += f" [{pulse['ioc_count']} IOCs]"
            parts.append(line)
            if pulse.get("description"):
                parts.append(f"  {pulse['description'][:200]}")
            if pulse.get("tags"):
                parts.append(f"  Tags: {', '.join(pulse['tags'][:6])}")
            if pulse.get("targeted_countries"):
                parts.append(f"  Targeted: {', '.join(pulse['targeted_countries'][:5])}")
            if pulse.get("iocs_sample"):
                parts.append(f"  Sample IOCs: {'; '.join(pulse['iocs_sample'][:3])}")

    return "\n".join(parts) if parts else "No additional research data available."
