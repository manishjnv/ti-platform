"""Cyber news ingestion service — RSS/Atom feed fetcher + AI enrichment.

Fetches articles from major cybersecurity news sources, deduplicates via
source_hash, and queues AI enrichment for structured intelligence extraction.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.ai import chat_completion

logger = get_logger(__name__)
settings = get_settings()


# ── RSS Feed Sources ─────────────────────────────────────

NEWS_FEEDS: list[dict] = [
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "default_category": "active_threats",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "default_category": "active_threats",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "default_category": "ransomware_breaches",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "default_category": "security_research",
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "default_category": "active_threats",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "default_category": "exploited_vulnerabilities",
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "default_category": "active_threats",
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/feed",
        "default_category": "nation_state",
    },
]


def _hash(text: str) -> str:
    """SHA-256 hash for dedup."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_pub_date(date_str: str | None) -> datetime | None:
    """Parse RSS pubDate / Atom updated to datetime."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        pass
    # Try ISO format
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _strip_html(html: str | None) -> str:
    """Remove HTML tags, decode entities."""
    if not html:
        return ""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:5000]  # cap long descriptions


def _detect_category(title: str, description: str) -> str:
    """Simple keyword-based category detection. AI enrichment refines later."""
    text = f"{title} {description}".lower()

    if any(k in text for k in ("ransomware", "breach", "leak", "stolen data", "extortion")):
        return "ransomware_breaches"
    if any(k in text for k in ("exploit", "vulnerability", "cve-", "zero-day", "0-day", "patch", "kev")):
        return "exploited_vulnerabilities"
    if any(k in text for k in ("apt", "nation-state", "nation state", "china", "russia", "iran", "north korea", "espionage")):
        return "nation_state"
    if any(k in text for k in ("cloud", "saas", "azure", "aws", "identity", "oauth", "sso", "credential")):
        return "cloud_identity"
    if any(k in text for k in ("ics", "ot ", "scada", "plc", "industrial", "operational technology")):
        return "ot_ics"
    if any(k in text for k in ("tool", "framework", "open source", "github", "release", "platform")):
        return "tools_technology"
    if any(k in text for k in ("policy", "regulation", "compliance", "gdpr", "law", "legislation", "executive order")):
        return "policy_regulation"
    if any(k in text for k in ("research", "analysis", "report", "study", "paper", "findings")):
        return "security_research"

    return "active_threats"


async def fetch_rss_feed(feed: dict) -> list[dict]:
    """Fetch and parse a single RSS/Atom feed. Returns list of raw article dicts."""
    articles: list[dict] = []

    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            headers = {
                "User-Agent": "IntelWatch/1.0 (Cyber News Aggregator)",
                "Accept": "application/rss+xml, application/xml, text/xml, */*",
            }
            resp = await client.get(feed["url"], headers=headers)
            resp.raise_for_status()
            content = resp.text

        root = ElementTree.fromstring(content)

        # Detect RSS vs Atom
        ns = {"atom": "http://www.w3.org/2005/Atom"}

        # RSS 2.0
        items = root.findall(".//item")
        if items:
            for item in items:
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub_date = item.findtext("pubDate") or item.findtext("date")
                desc_raw = item.findtext("description") or item.findtext("content:encoded") or ""

                if not title or not link:
                    continue

                description = _strip_html(desc_raw)
                category = _detect_category(title, description)
                source_hash = _hash(f"{feed['name']}:{link}")

                articles.append({
                    "headline": title,
                    "source": feed["name"],
                    "source_url": link,
                    "published_at": _parse_pub_date(pub_date),
                    "category": category,
                    "raw_content": description,
                    "source_hash": source_hash,
                })
        else:
            # Atom format
            entries = root.findall("atom:entry", ns) or root.findall("entry")
            for entry in entries:
                title = (entry.findtext("atom:title", namespaces=ns) or entry.findtext("title") or "").strip()
                link_el = entry.find("atom:link[@rel='alternate']", ns) or entry.find("atom:link", ns) or entry.find("link")
                link = ""
                if link_el is not None:
                    link = link_el.get("href", "").strip()

                pub_date = entry.findtext("atom:updated", namespaces=ns) or entry.findtext("atom:published", namespaces=ns) or entry.findtext("updated") or entry.findtext("published")
                desc_raw = entry.findtext("atom:summary", namespaces=ns) or entry.findtext("atom:content", namespaces=ns) or entry.findtext("summary") or entry.findtext("content") or ""

                if not title or not link:
                    continue

                description = _strip_html(desc_raw)
                category = _detect_category(title, description)
                source_hash = _hash(f"{feed['name']}:{link}")

                articles.append({
                    "headline": title,
                    "source": feed["name"],
                    "source_url": link,
                    "published_at": _parse_pub_date(pub_date),
                    "category": category,
                    "raw_content": description,
                    "source_hash": source_hash,
                })

        logger.info("news_feed_fetched", source=feed["name"], count=len(articles))

    except httpx.TimeoutException:
        logger.warning("news_feed_timeout", source=feed["name"])
    except Exception as e:
        logger.warning("news_feed_error", source=feed["name"], error=str(e)[:200])

    return articles


async def fetch_all_feeds() -> list[dict]:
    """Fetch all configured RSS feeds concurrently."""
    import asyncio
    tasks = [fetch_rss_feed(feed) for feed in NEWS_FEEDS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_articles: list[dict] = []
    for result in results:
        if isinstance(result, list):
            all_articles.extend(result)
        elif isinstance(result, Exception):
            logger.warning("news_feed_exception", error=str(result)[:200])

    logger.info("news_all_feeds_fetched", total=len(all_articles))
    return all_articles


# ── AI Enrichment ────────────────────────────────────────

_NEWS_ENRICHMENT_SYSTEM = """You are a senior cyber threat intelligence analyst. Given a cybersecurity news article headline and content, produce a structured JSON analysis.

Return ONLY valid JSON with this exact schema (no markdown, no backticks):
{
  "category": "one of: active_threats, exploited_vulnerabilities, ransomware_breaches, nation_state, cloud_identity, ot_ics, security_research, tools_technology, policy_regulation",
  "summary": "2-3 sentence executive summary",
  "why_it_matters": ["1-3 bullet points for SOC/CISO decision-makers"],
  "tags": ["relevant keywords/tags"],
  "threat_actors": ["named threat actor groups, empty if none"],
  "malware_families": ["named malware families, empty if none"],
  "campaign_name": "campaign name or null",
  "cves": ["CVE-YYYY-NNNNN format, empty if none"],
  "vulnerable_products": ["affected software/hardware"],
  "tactics_techniques": ["MITRE ATT&CK technique IDs like T1566, T1190"],
  "initial_access_vector": "primary initial access method or null",
  "post_exploitation": ["post-exploitation activities observed"],
  "targeted_sectors": ["industry sectors targeted"],
  "targeted_regions": ["geographic regions targeted"],
  "impacted_assets": ["types of assets impacted"],
  "ioc_summary": {"domains": [], "ips": [], "hashes": [], "urls": []},
  "timeline": [{"date": "YYYY-MM-DD or null", "event": "description"}],
  "detection_opportunities": ["detection/hunting opportunities"],
  "mitigation_recommendations": ["actionable mitigation steps"],
  "confidence": "high, medium, or low",
  "relevance_score": 50
}

Scoring guidelines for relevance_score (1-100):
- 90-100: Active exploitation, zero-day, KEV addition, critical infrastructure
- 70-89: Enterprise-impact vulnerability, major breach, APT campaign
- 50-69: Notable research, tool release, moderate vulnerability
- 30-49: Policy update, minor tool, informational
- 1-29: Low-impact, historical, opinion piece"""


async def enrich_news_item(headline: str, raw_content: str) -> dict | None:
    """Use AI to extract structured intelligence from a news article."""
    user_prompt = f"Headline: {headline}\n\nContent:\n{raw_content[:3000]}"

    result = await chat_completion(
        system_prompt=_NEWS_ENRICHMENT_SYSTEM,
        user_prompt=user_prompt,
        max_tokens=1200,
        temperature=0.2,
    )

    if not result:
        return None

    # Parse JSON from response (strip markdown fences if present)
    text = result.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
        return data
    except json.JSONDecodeError:
        logger.warning("news_ai_json_parse_error", headline=headline[:80])
        return None
