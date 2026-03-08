"""Cyber news ingestion service — RSS/Atom feed fetcher + AI enrichment.

Fetches articles from major cybersecurity news sources, deduplicates via
source_hash, and queues AI enrichment for structured intelligence extraction.
"""

from __future__ import annotations

from app.prompts import (
    NEWS_ENRICHMENT_PROMPT,
    PROMPT_VERSION_NEWS_ENRICHMENT,
)

import hashlib
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree

import httpx
import trafilatura

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.ai import chat_completion_json

logger = get_logger(__name__)
settings = get_settings()


# ── RSS Feed Sources ─────────────────────────────────────

NEWS_FEEDS: list[dict] = [
    # ── Tier 1 — Major Security News ──────────────────
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
        "name": "The Record",
        "url": "https://therecord.media/feed",
        "default_category": "nation_state",
    },
    {
        "name": "CyberScoop",
        "url": "https://cyberscoop.com/feed/",
        "default_category": "nation_state",
    },
    # ── Tier 2 — Government / CERT Advisories ────────
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "default_category": "exploited_vulnerabilities",
    },
    # ── Tier 3 — Vendor Threat Research Blogs ────────
    {
        "name": "Microsoft Security",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "default_category": "security_research",
    },
    {
        "name": "Google TAG",
        "url": "https://blog.google/threat-analysis-group/rss/",
        "default_category": "nation_state",
    },
    {
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "default_category": "security_research",
    },
    {
        "name": "SentinelOne Labs",
        "url": "https://www.sentinelone.com/labs/feed/",
        "default_category": "security_research",
    },
    {
        "name": "Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "default_category": "security_research",
    },
    {
        "name": "Sophos News",
        "url": "https://news.sophos.com/en-us/category/threat-research/feed/",
        "default_category": "active_threats",
    },
    {
        "name": "WeLiveSecurity",
        "url": "https://www.welivesecurity.com/en/rss/feed/",
        "default_category": "security_research",
    },
    {
        "name": "Mandiant",
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
        "default_category": "nation_state",
    },
    # ── Tier 4 — Expert / Independent ────────────────
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/blog/atom.xml",
        "default_category": "policy_regulation",
    },
    {
        "name": "Graham Cluley",
        "url": "https://grahamcluley.com/feed/",
        "default_category": "active_threats",
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "default_category": "active_threats",
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
    return text[:12000]  # cap long descriptions


# ── Cross-source Deduplication ───────────────────────────

# Stop-words stripped before comparing headlines
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "in", "on", "at", "to",
    "for", "of", "and", "or", "but", "by", "with", "from", "up", "as",
    "it", "its", "that", "this", "how", "what", "why", "who", "new",
    "has", "have", "had", "not", "no", "be", "been", "being",
    "can", "could", "will", "would", "may", "might", "about", "over",
    "after", "more", "than", "all", "get", "got", "into", "out",
})


def _headline_tokens(headline: str) -> set[str]:
    """Tokenize a headline into a set of meaningful lowercase words.

    Applies simple suffix stripping so 'patches'/'patched'/'patching' all
    normalise to the same stem, improving cross-source matching.
    """
    words = re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", headline.lower())
    tokens: set[str] = set()
    for w in words:
        if w in _STOP_WORDS or len(w) <= 1:
            continue
        # Keep CVE IDs and numbers intact
        if re.match(r"^cve-\d{4}-\d+$", w) or re.match(r"^\d+$", w):
            tokens.add(w)
            continue
        # Simple suffix stripping (poor man's stemmer)
        stem = w
        for suffix in ("ting", "ing", "ied", "ies", "ity", "ness", "ment",
                        "ous", "ive", "able", "ble", "ful", "less",
                        "ated", "ates", "tion", "sion",
                        "ed", "es", "ly", "er", "al", "en"):
            if stem.endswith(suffix) and len(stem) - len(suffix) >= 3:
                stem = stem[:-len(suffix)]
                break
        # Trailing 's' after stripping
        if stem.endswith("s") and len(stem) > 3:
            stem = stem[:-1]
        tokens.add(stem)
    return tokens


def _headline_similarity(a: str, b: str) -> float:
    """Jaccard similarity between two headline token sets (0.0 – 1.0).

    Automatically boosts score if both headlines reference the same CVE ID.
    """
    ta, tb = _headline_tokens(a), _headline_tokens(b)
    if not ta or not tb:
        return 0.0

    # Shared CVE IDs are a very strong duplicate signal
    cve_a = {t for t in ta if t.startswith("cve-")}
    cve_b = {t for t in tb if t.startswith("cve-")}
    if cve_a and cve_a & cve_b:
        return max(0.80, len(ta & tb) / len(ta | tb))

    return len(ta & tb) / len(ta | tb)


DUPLICATE_SIMILARITY_THRESHOLD = 0.40  # ≥40 % token overlap = same story


# ── Full-text Extraction ─────────────────────────────────

async def _extract_full_text(url: str) -> str | None:
    """Fetch the article URL and extract full body text using trafilatura.

    Returns the full article text (capped at 8 000 chars) or None on failure.
    This gives the AI enrichment pipeline the complete article instead of
    the short RSS summary.
    """
    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/124.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        text = trafilatura.extract(
            resp.text,
            include_comments=False,
            include_tables=False,
            no_fallback=False,
        )
        if text and len(text) > 200:
            return text[:12000]
        return None
    except Exception:
        return None


async def _enrich_articles_with_fulltext(articles: list[dict]) -> list[dict]:
    """Concurrently fetch full article text for a batch of articles.

    Replaces the short RSS description in raw_content with the complete
    article body when extraction succeeds.
    """
    import asyncio

    async def _fetch_one(article: dict) -> dict:
        full = await _extract_full_text(article["source_url"])
        if full:
            article["raw_content"] = full
            logger.debug(
                "fulltext_extracted",
                source=article["source"],
                chars=len(full),
            )
        return article

    # Process up to 10 concurrently to be polite to source sites
    sem = asyncio.Semaphore(10)

    async def _limited(art: dict) -> dict:
        async with sem:
            return await _fetch_one(art)

    return await asyncio.gather(*[_limited(a) for a in articles])


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


async def fetch_rss_feed(feed: dict) -> dict:
    """Fetch and parse a single RSS/Atom feed. Returns dict with articles and status info."""
    articles: list[dict] = []
    status_info = {
        "source_name": feed["name"],
        "source_url": feed["url"],
        "status": "ok",
        "articles_count": 0,
        "error": None,
    }

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

        status_info["articles_count"] = len(articles)
        logger.info("news_feed_fetched", source=feed["name"], count=len(articles))

    except httpx.TimeoutException:
        status_info["status"] = "timeout"
        status_info["error"] = "Connection timed out"
        logger.warning("news_feed_timeout", source=feed["name"])
    except Exception as e:
        status_info["status"] = "error"
        status_info["error"] = str(e)[:500]
        logger.warning("news_feed_error", source=feed["name"], error=str(e)[:200])

    return {"articles": articles, "status": status_info}


# ── Headline Relevance Pre-Scorer ────────────────────────
# Used during ingestion to rank articles BEFORE storing them.
# This lets us keep only the top N most relevant articles per cycle
# so AI enrichment can keep pace and every displayed article is high-quality.

# High-value keywords (each hit adds points)
_RELEVANCE_KEYWORDS: list[tuple[list[str], int]] = [
    # Active exploitation / zero-day (highest value)
    (["zero-day", "0-day", "actively exploited", "in the wild", "kev", "cisa adds"], 25),
    # CVEs, vulnerabilities
    (["cve-", "critical vulnerability", "rce", "remote code execution", "privilege escalation"], 20),
    # Named threat actors / APTs
    (["apt", "lazarus", "cozy bear", "fancy bear", "turla", "sandworm", "volt typhoon",
      "midnight blizzard", "scattered spider", "lockbit", "blackcat", "alphv", "clop",
      "conti", "revil", "unc", "ta5", "fin7", "fin11"], 20),
    # Ransomware / major breaches
    (["ransomware", "data breach", "million records", "extortion", "leaked"], 18),
    # Malware families
    (["malware", "trojan", "backdoor", "rootkit", "infostealer", "rat", "botnet",
      "cobalt strike", "mimikatz", "loader"], 15),
    # Government / nation-state
    (["nation-state", "nation state", "espionage", "cyber command", "nsa", "gchq",
      "fbi", "cisa", "indictment", "sanctions"], 15),
    # Tactical content (detections, IOCs)
    (["ioc", "indicator", "sigma rule", "yara", "snort", "suricata", "detection",
      "hunting", "forensic"], 12),
    # Major vendors (product-specific vulns)
    (["microsoft", "google", "apple", "cisco", "palo alto", "fortinet", "vmware",
      "citrix", "ivanti", "sophos", "crowdstrike", "okta", "snowflake"], 10),
    # Supply chain
    (["supply chain", "npm", "pypi", "solarwinds", "3cx", "moveit"], 15),
    # Cloud / identity
    (["azure", "aws", "gcp", "entra", "oauth", "saml", "sso"], 10),
]

# Low-value patterns (reduce score — generic, non-actionable content)
_LOW_VALUE_KEYWORDS: list[tuple[list[str], int]] = [
    (["podcast", "webinar", "register now", "sponsored", "infographic"], -30),
    (["job opening", "career", "hiring", "salary"], -30),
    (["product launch", "new feature", "announces partnership"], -15),
    (["opinion:", "editorial", "book review", "interview with"], -10),
]

# Source tier bonus (applied once per article)
_SOURCE_TIER_BONUS: dict[str, int] = {
    # Tier 1 — Major breaking news
    "BleepingComputer": 10, "The Hacker News": 10, "Krebs on Security": 12,
    "Dark Reading": 8, "SecurityWeek": 8, "The Record": 10, "CyberScoop": 8,
    # Tier 2 — Government / CERT
    "CISA Alerts": 15,
    # Tier 3 — Vendor research (deep technical)
    "Microsoft Security": 10, "Google TAG": 12, "Cisco Talos": 10,
    "SentinelOne Labs": 10, "Unit 42": 12, "Mandiant": 12,
    "Sophos News": 8, "WeLiveSecurity": 8,
    # Tier 4 — Independent
    "Schneier on Security": 6, "Graham Cluley": 5, "Threatpost": 5,
}


def _pre_score_article(article: dict) -> int:
    """Compute a quick relevance score for an article based on headline + description.

    Returns an integer score (higher = more relevant).
    Used to rank articles before storing so we only keep the best per cycle.
    """
    text = f"{article['headline']} {article.get('raw_content', '')[:2000]}".lower()
    score = 0

    # Keyword scoring
    for keywords, points in _RELEVANCE_KEYWORDS:
        if any(k in text for k in keywords):
            score += points

    # Low-value penalty
    for keywords, penalty in _LOW_VALUE_KEYWORDS:
        if any(k in text for k in keywords):
            score += penalty  # penalty is negative

    # Source tier bonus
    score += _SOURCE_TIER_BONUS.get(article.get("source", ""), 0)

    # Recency bonus: articles less than 6 hours old get +10
    pub = article.get("published_at")
    if pub:
        try:
            from datetime import timedelta
            age = datetime.now(timezone.utc) - pub
            if age < timedelta(hours=6):
                score += 10
            elif age < timedelta(hours=24):
                score += 5
        except Exception:
            pass

    return max(0, score)


# Maximum articles to keep per ingestion cycle.
# 15/hour target ÷ 2 cycles/hour = ~8 per cycle (round up to 10 for buffer)
MAX_ARTICLES_PER_CYCLE = 10


async def _persist_feed_statuses(statuses: list[dict]) -> None:
    """Persist per-feed status to the news_feed_status table."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from app.core.database import async_session_factory
    from app.models.models import NewsFeedStatus

    try:
        async with async_session_factory() as session:
            now = datetime.now(timezone.utc)
            for st in statuses:
                name = st.get("source_name", "")
                if not name:
                    continue

                values = {
                    "source_name": name,
                    "source_url": st.get("source_url", ""),
                    "status": st.get("status", "unknown"),
                    "last_checked": now,
                    "articles_last_fetch": st.get("articles_count", 0),
                    "total_articles": st.get("articles_count", 0),
                    "updated_at": now,
                }

                if st.get("status") == "ok":
                    values["last_success"] = now
                    values["consecutive_failures"] = 0
                    values["last_error"] = None
                else:
                    values["last_failure"] = now
                    values["last_error"] = st.get("error")

                stmt = pg_insert(NewsFeedStatus).values(**values)
                update_dict = {k: v for k, v in values.items() if k != "source_name"}

                if st.get("status") == "ok":
                    update_dict["total_articles"] = NewsFeedStatus.total_articles + st.get("articles_count", 0)
                    update_dict["consecutive_failures"] = 0
                else:
                    update_dict["consecutive_failures"] = NewsFeedStatus.consecutive_failures + 1

                stmt = stmt.on_conflict_do_update(
                    index_elements=["source_name"],
                    set_=update_dict,
                )
                await session.execute(stmt)

            await session.commit()
    except Exception as e:
        logger.warning("news_feed_status_persist_error", error=str(e)[:200])


async def get_news_feed_statuses() -> list:
    """Get all news feed statuses from the database."""
    from sqlalchemy import select
    from app.core.database import async_session_factory
    from app.models.models import NewsFeedStatus

    async with async_session_factory() as session:
        result = await session.execute(
            select(NewsFeedStatus).order_by(NewsFeedStatus.source_name)
        )
        return result.scalars().all()


async def get_news_pipeline_status() -> dict:
    """Compute overall pipeline health: stale detection, source health, last article time.

    Returns a dict matching NewsPipelineStatusResponse schema:
      is_stale, stored_last_hour, stored_last_24h,
      total_sources_ok, total_sources_failing,
      last_article_at, status
    """
    from sqlalchemy import select, func
    from app.core.database import async_session_factory
    from app.models.models import NewsItem, NewsFeedStatus

    from datetime import timedelta

    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    twenty_four_hours_ago = now - timedelta(hours=24)

    async with async_session_factory() as session:
        # Articles stored in last hour
        r1 = await session.execute(
            select(func.count(NewsItem.id)).where(NewsItem.created_at >= one_hour_ago)
        )
        stored_last_hour = r1.scalar() or 0

        # Articles stored in last 24 hours
        r2 = await session.execute(
            select(func.count(NewsItem.id)).where(NewsItem.created_at >= twenty_four_hours_ago)
        )
        stored_last_24h = r2.scalar() or 0

        # Most recent article timestamp
        r3 = await session.execute(
            select(func.max(NewsItem.created_at))
        )
        last_article_at = r3.scalar()

        # Source health from news_feed_status table
        r4 = await session.execute(
            select(
                func.count(NewsFeedStatus.source_name).filter(NewsFeedStatus.status == "ok").label("ok"),
                func.count(NewsFeedStatus.source_name).filter(NewsFeedStatus.status != "ok").label("failing"),
            )
        )
        source_row = r4.one()
        total_sources_ok = source_row.ok or 0
        total_sources_failing = source_row.failing or 0

    is_stale = stored_last_hour == 0
    # Determine status
    if total_sources_ok == 0 and total_sources_failing > 0:
        status = "down"
    elif is_stale and total_sources_failing > 0:
        status = "degraded"
    elif is_stale:
        status = "stale"
    else:
        status = "ok"

    return {
        "is_stale": is_stale,
        "stored_last_hour": stored_last_hour,
        "stored_last_24h": stored_last_24h,
        "total_sources_ok": total_sources_ok,
        "total_sources_failing": total_sources_failing,
        "last_article_at": last_article_at,
        "status": status,
    }


async def fetch_all_feeds(known_hashes: set[str] | None = None) -> list[dict]:
    """Fetch all configured RSS feeds concurrently, then extract full article text.

    Pre-scores every article by headline relevance and keeps only the top
    MAX_ARTICLES_PER_CYCLE articles.  This ensures AI enrichment can keep pace
    and only high-quality content enters the pipeline.

    Args:
        known_hashes: Set of source_hash values already in the database.
            Articles matching these hashes are excluded *before* the top-N
            cut so that new articles aren't crowded out by already-ingested
            high-scoring stories.

    Also persists per-feed status to news_feed_status table.
    """
    import asyncio
    tasks = [fetch_rss_feed(feed) for feed in NEWS_FEEDS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_articles: list[dict] = []
    feed_statuses: list[dict] = []

    for result in results:
        if isinstance(result, dict):
            all_articles.extend(result.get("articles", []))
            feed_statuses.append(result.get("status", {}))
        elif isinstance(result, Exception):
            logger.warning("news_feed_exception", error=str(result)[:200])

    # Persist feed statuses
    await _persist_feed_statuses(feed_statuses)

    logger.info("news_rss_fetched", total=len(all_articles), sources=len(NEWS_FEEDS))

    if not all_articles:
        return []

    # ── Filter out already-ingested articles ─────────────
    # This MUST happen before the top-N cut; otherwise the same
    # high-scoring articles that were already stored keep occupying
    # all slots and genuinely new articles never reach the DB.
    if known_hashes:
        before = len(all_articles)
        all_articles = [a for a in all_articles if a["source_hash"] not in known_hashes]
        filtered = before - len(all_articles)
        if filtered:
            logger.info(
                "news_known_hash_filter",
                before=before,
                after=len(all_articles),
                filtered=filtered,
            )

    if not all_articles:
        return []

    # ── Score and rank articles ──────────────────────────
    for art in all_articles:
        art["_pre_score"] = _pre_score_article(art)

    # Sort by pre-score descending, then by recency
    all_articles.sort(
        key=lambda a: (a["_pre_score"], a.get("published_at") or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )

    # Keep only top N
    kept = all_articles[:MAX_ARTICLES_PER_CYCLE]
    dropped = len(all_articles) - len(kept)
    if dropped > 0:
        logger.info(
            "news_pre_score_filter",
            total=len(all_articles),
            kept=len(kept),
            dropped=dropped,
            min_score=kept[-1]["_pre_score"] if kept else 0,
            max_score=kept[0]["_pre_score"] if kept else 0,
        )

    # Clean up internal scoring key
    for art in kept:
        art.pop("_pre_score", None)

    # Extract full article text (replaces short RSS summaries)
    kept = list(await _enrich_articles_with_fulltext(kept))
    full_count = sum(1 for a in kept if len(a.get("raw_content", "")) > 1000)
    logger.info(
        "news_fulltext_done",
        total=len(kept),
        full_text=full_count,
    )

    return kept


# ── AI Enrichment ────────────────────────────────────────
# Prompt moved to app/prompts.py — import aliases for backward compat
_NEWS_ENRICHMENT_PROMPT_VERSION = PROMPT_VERSION_NEWS_ENRICHMENT
_NEWS_ENRICHMENT_SYSTEM = NEWS_ENRICHMENT_PROMPT


async def enrich_news_item(
    headline: str,
    raw_content: str,
    *,
    source_name: str = "",
    published_date: str | None = None,
    existing_tags: list[str] | None = None,
) -> dict | None:
    """Use AI to extract structured intelligence from a news article."""
    parts = [f"Headline: {headline}"]
    if source_name:
        parts.append(f"Source: {source_name}")
    if published_date:
        parts.append(f"Published: {published_date}")
    if existing_tags:
        parts.append(f"Tags: {', '.join(existing_tags[:15])}")
    parts.append(f"\nContent:\n{raw_content[:10000]}")
    user_prompt = "\n".join(parts)

    data = await chat_completion_json(
        system_prompt=_NEWS_ENRICHMENT_SYSTEM,
        user_prompt=user_prompt,
        max_tokens=6000,
        temperature=0.15,
        required_keys=["category", "summary", "executive_brief"],
        caller="news_enrichment",
        feature="news_enrichment",
    )

    if not data:
        return None

    data["_prompt_version"] = _NEWS_ENRICHMENT_PROMPT_VERSION
    return data
