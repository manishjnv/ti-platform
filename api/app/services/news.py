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
import trafilatura

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.ai import chat_completion

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
                # Use explicit 'is not None' checks — ElementTree Elements
                # with no children are falsy, so 'or' chains skip valid <link/> tags.
                link_el = entry.find("atom:link[@rel='alternate']", ns)
                if link_el is None:
                    link_el = entry.find("atom:link", ns)
                if link_el is None:
                    link_el = entry.find("link")
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


# ── Hourly Rate Control ──────────────────────────────────
# Target: min 4, max 15 NEW articles per hour.
# 4 cycles/hour (every 15 min) → target ~4 per cycle, cap adjusts dynamically.
MAX_ARTICLES_PER_HOUR = 15
MIN_ARTICLES_PER_HOUR = 4
DEFAULT_PER_CYCLE = 5  # Normal per-cycle cap (4 cycles × 5 = 20, trimmed to 15/hr)


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
            select(NewsFeedStatus).order_by(NewsFeedStatus.total_articles.desc())
        )
        return result.scalars().all()


async def get_news_pipeline_status() -> dict:
    """Check overall news pipeline health — is it stale?

    Returns a dict with: is_stale, stored_last_hour, stored_last_24h,
    total_sources_ok, total_sources_failing, last_article_at, status.
    """
    from sqlalchemy import select, func as sqlfunc
    from app.core.database import async_session_factory
    from app.models.models import NewsItem, NewsFeedStatus

    async with async_session_factory() as session:
        now = datetime.now(timezone.utc)
        from datetime import timedelta as _td
        one_hour_ago = now - _td(hours=1)
        twenty_four_h_ago = now - _td(hours=24)

        # Count articles stored in last 1 hour
        r1 = await session.execute(
            select(sqlfunc.count(NewsItem.id)).where(NewsItem.created_at >= one_hour_ago)
        )
        stored_last_hour = r1.scalar() or 0

        # Count articles stored in last 24 hours
        r24 = await session.execute(
            select(sqlfunc.count(NewsItem.id)).where(NewsItem.created_at >= twenty_four_h_ago)
        )
        stored_last_24h = r24.scalar() or 0

        # Last article timestamp
        r_last = await session.execute(
            select(sqlfunc.max(NewsItem.created_at))
        )
        last_article_at = r_last.scalar()

        # Feed source health
        feed_rows = await session.execute(select(NewsFeedStatus))
        feeds = feed_rows.scalars().all()
        sources_ok = sum(1 for f in feeds if f.status == "ok")
        sources_failing = sum(1 for f in feeds if f.status in ("error", "timeout"))

    is_stale = stored_last_hour == 0
    # Determine overall status
    if sources_ok == 0 and len(feeds) > 0:
        status = "down"
    elif is_stale and sources_failing > sources_ok:
        status = "degraded"
    elif is_stale:
        status = "stale"
    else:
        status = "ok"

    return {
        "is_stale": is_stale,
        "stored_last_hour": stored_last_hour,
        "stored_last_24h": stored_last_24h,
        "total_sources_ok": sources_ok,
        "total_sources_failing": sources_failing,
        "last_article_at": last_article_at,
        "status": status,
    }


async def fetch_all_feeds(
    known_hashes: set[str] | None = None,
    stored_last_hour: int = 0,
    source_24h_counts: dict[str, int] | None = None,
) -> dict:
    """Fetch all configured RSS feeds concurrently, then extract full article text.

    Returns a dict with keys:
      - "articles": list of article dicts ready for dedup + storage
      - "cycle_cap": how many NEW articles should be stored this cycle

    Implements intelligent rate control:
    - Dynamic per-cycle cap based on how many articles were stored in the last hour
      (target: min 4, max 15 per hour).
    - Source diversity: guarantees at least 1 article per source per day for sources
      that haven't appeared in the last 24h — reserves slots before score-ranking.
    - Returns a 3× buffer so the caller's cross-source dedup can reject some
      articles and still fill the cycle_cap with genuinely new stories.
    - Articles whose source_hash already exists in `known_hashes` are filtered out
      BEFORE the cap so that new content always gets a chance.

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
        return {"articles": [], "cycle_cap": 0}

    # ── Filter out already-stored articles BEFORE scoring ─
    if known_hashes:
        before = len(all_articles)
        all_articles = [a for a in all_articles if a.get("source_hash") not in known_hashes]
        skipped = before - len(all_articles)
        if skipped:
            logger.info("news_pre_dedup", before=before, after=len(all_articles), skipped=skipped)

    if not all_articles:
        return {"articles": [], "cycle_cap": 0}

    # ── Dynamic per-cycle cap ────────────────────────────
    # How many more articles can we store this hour?
    headroom = max(0, MAX_ARTICLES_PER_HOUR - stored_last_hour)
    # If below minimum floor, allow a burst to catch up
    if stored_last_hour < MIN_ARTICLES_PER_HOUR:
        cycle_cap = max(DEFAULT_PER_CYCLE, MIN_ARTICLES_PER_HOUR - stored_last_hour)
    else:
        cycle_cap = min(DEFAULT_PER_CYCLE, headroom)
    # At least 1 per cycle to keep pipeline active
    cycle_cap = max(1, cycle_cap)
    logger.info("news_rate_control", stored_last_hour=stored_last_hour, headroom=headroom, cycle_cap=cycle_cap)

    # ── Score all articles ───────────────────────────────
    for art in all_articles:
        art["_pre_score"] = _pre_score_article(art)

    # Sort by pre-score descending, then by recency
    all_articles.sort(
        key=lambda a: (a["_pre_score"], a.get("published_at") or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )

    # ── Source diversity: reserve slots for under-represented sources ─
    source_counts_24h = source_24h_counts or {}
    # Find sources with 0 articles in last 24h
    underserved_sources = set()
    for feed in NEWS_FEEDS:
        if source_counts_24h.get(feed["name"], 0) == 0:
            underserved_sources.add(feed["name"])

    reserved: list[dict] = []  # 1 best article per underserved source
    remaining: list[dict] = []

    if underserved_sources:
        # Pick the highest-scored article per underserved source
        picked_sources: set[str] = set()
        for art in all_articles:
            src = art.get("source", "")
            if src in underserved_sources and src not in picked_sources:
                reserved.append(art)
                picked_sources.add(src)
            else:
                remaining.append(art)
        logger.info("news_source_diversity", reserved=len(reserved), underserved=len(underserved_sources))
    else:
        remaining = list(all_articles)

    # ── Fill remaining slots from top-scored ──────────────
    # Return 3× cycle_cap buffer so caller's cross-source dedup can
    # reject some articles and still fill the cycle_cap with new stories.
    buffer_size = cycle_cap * 3
    slots_left = max(0, buffer_size - len(reserved))
    # Avoid duplicates: remove reserved hashes from remaining
    reserved_hashes = {a.get("source_hash") for a in reserved}
    filler = [a for a in remaining if a.get("source_hash") not in reserved_hashes][:slots_left]

    kept = reserved + filler
    # Cap total buffer (diversity reservations + filler)
    max_total = min(buffer_size + len(reserved), MAX_ARTICLES_PER_HOUR * 2)
    kept = kept[:max_total]

    dropped = len(all_articles) - len(kept)
    if dropped > 0:
        logger.info(
            "news_pre_score_filter",
            total=len(all_articles),
            kept=len(kept),
            dropped=dropped,
            reserved_diversity=len(reserved),
            min_score=min((a["_pre_score"] for a in kept), default=0),
            max_score=max((a["_pre_score"] for a in kept), default=0),
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

    return {"articles": kept, "cycle_cap": cycle_cap}


# ── AI Enrichment ────────────────────────────────────────

_NEWS_ENRICHMENT_SYSTEM = """You are a senior cyber threat intelligence analyst at a Fortune 100 SOC. You write for two audiences: a CISO who needs business-impact framing in ≤60 seconds, and a SOC analyst who needs detection rules and IOC-actionable details.

Given a cybersecurity news headline + content, produce a structured JSON intelligence brief.

## FORMATTING RULES — MANDATORY

1. **USE BULLET POINTS** everywhere possible. Every array field (why_it_matters, detection_opportunities, mitigation_recommendations, post_exploitation) must use SHORT, punchy bullet items — never paragraphs.
2. **COMPRESS AGGRESSIVELY** — strip every filler word. Each bullet/sentence must deliver a NEW fact. Target 50% fewer words than a typical article summary. If a sentence adds no new information beyond what's already stated, DELETE it.
3. **HIGHLIGHT ENTITIES INLINE** — always name-drop: threat actor names, CVE IDs, product names with versions, campaign names, dates (YYYY-MM-DD), organization names, specific attack techniques. These get highlighted in the UI automatically.
4. **NO DUPLICATE INFORMATION** — do not repeat the same fact across summary, executive_brief, risk_assessment, and why_it_matters. Each field has a DIFFERENT purpose:
   - summary: WHAT happened + WHO affected (2-3 sentences)
   - executive_brief: Full technical narrative for a CISO briefing
   - risk_assessment: WHO is at risk + business impact
   - attack_narrative: HOW the attack works step-by-step
   - why_it_matters: ACTION ITEMS for defenders
5. **NO GENERIC ADVICE** — every bullet must contain at least one SPECIFIC name (CVE, product, tool, actor, date, version, organization).
6. **BOLD KEY INTELLIGENCE** — In summary, executive_brief, risk_assessment, and attack_narrative fields, wrap the most important technical terms in **double asterisks** for visual emphasis. Bold ONLY these categories:
   - **Organization/victim names**: company names, government agencies, targeted entities (e.g., **AkzoNobel**, **Microsoft**, **CISA**)
   - **Threat actor & malware names**: APT groups, ransomware families, tools (e.g., **Anubis ransomware**, **Lazarus Group**, **Cobalt Strike**)
   - **Data quantities & impact metrics**: stolen data size, record counts, financial impact (e.g., **170GB**, **2.3 million records**, **$4.5M ransom**)
   - **Attack techniques & tools**: specific methods used (e.g., **data wiper**, **credential stuffing**, **supply chain compromise**)
   - **Data types compromised**: what was leaked/stolen (e.g., **confidential agreements**, **email addresses**, **source code**)
   - **Remediation actions taken**: containment/response status (e.g., **contained the breach**, **patched within 24h**, **services restored**)
   - **Industry/sector names**: when relevant to targeting (e.g., **chemical manufacturing**, **defense contractor**)
   - **Product names with versions**: affected software (e.g., **PAN-OS 10.2**, **Exchange Server 2019**, **VMware Aria Operations 8.x**)
   - **Vulnerability/flaw names**: the type of flaw or weakness (e.g., **RCE flaw**, **SQL injection**, **buffer overflow**, **deserialization vulnerability**, **authentication bypass**)
   - **CVE identifiers**: always bold CVE IDs (e.g., **CVE-2025-12345**, **CVE-2024-3400**)
   - **Severity & CVSS ratings**: severity levels and scores (e.g., **critical severity**, **CVSS 9.8**, **high-severity**, **actively exploited**)
   - **Key dates & event timelines**: when events happened (e.g., **March 4, 2026**, **since January 2025**, **patched on February 28**)
   Do NOT bold common words, conjunctions, or entire sentences. Bold only the KEY noun phrases (1-5 words each). Aim for 8-20 bolded terms per text field.

## QUALITY RULES — READ CAREFULLY

**BANNED PHRASES (never use these — they are meaningless filler):**
- "timely patching is crucial", "apply patches and updates", "keep software up to date"
- "monitor for suspicious/unusual activity", "implement robust security controls"
- "organizations should prioritize security", "stay vigilant"
- "this incident highlights the importance of...", "this serves as a reminder..."
- "underscores the need for...", "reinforces the importance of..."
- Any sentence that could apply to ANY article generically is FILLER — delete it.

**REQUIRED QUALITY: every bullet/sentence must contain at least ONE of:**
- A specific technology, CVE, tool name, or protocol
- A concrete SIEM query, log source, or EDR detection
- A measurable action with a clear owner (e.g., "IAM team should audit OAuth app grants in Entra ID within 48h")
- A named threat group, malware hash, or campaign identifier
- A quantified business impact (dollar amount, number of records, downtime hours)
- A specific date, version number, or organization name

**EXAMPLES — BAD vs GOOD:**

why_it_matters BAD:  "Organizations should update their software to prevent exploitation."
why_it_matters GOOD: "CVE-2024-3400 is actively exploited in PAN-OS GlobalProtect; any org with internet-facing firewalls running PAN-OS 10.2/11.0/11.1 should patch to 10.2.9-h1+ within 24h or apply the Threat Prevention signature (ID 95187) as a workaround."

detection_opportunities BAD: "Monitor for suspicious network activity"
detection_opportunities GOOD: "Hunt for POST requests to /ssl-vpn/hipreport.php with shell metacharacters in the SESSID cookie — create a Suricata rule on content:\"/ssl-vpn/hipreport.php\"; pcre:\"/SESSID=.*[;|`$]/\""

mitigation_recommendations BAD: "Apply the latest security patches"
mitigation_recommendations GOOD: "Apply PAN-OS hotfix 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3. If patching requires a maintenance window, immediately enable Threat Prevention signature 95187 and disable device telemetry as an interim measure."

executive_brief BAD: "This vulnerability highlights the importance of timely patching and continuous monitoring."
executive_brief GOOD: "Volexity observed UTA0218 deploying a Python reverse shell through CVE-2024-3400 in PAN-OS GlobalProtect since March 26. The zero-day allows unauthenticated RCE via command injection in the device's session handling. Palo Alto Networks published an advisory (PAN-SA-2024-0015) with emergency hotfixes. CISA added it to the KEV catalog requiring federal agencies to patch by April 19. Impact: full device compromise, credential theft from running-config, and lateral movement using stolen firewall VPN credentials."

## JSON SCHEMA — return ONLY valid JSON, no markdown fences:
{
  "category": "active_threats|exploited_vulnerabilities|ransomware_breaches|nation_state|cloud_identity|ot_ics|security_research|tools_technology|policy_regulation",
  "summary": "2-3 SHORT sentences. Lead with WHAT happened + specific names/CVEs, then WHO is affected, then SO WHAT. Max 60 words.",
  "executive_brief": "5-8 sentences structured as: (1) What happened with specific names/dates, (2) Technical mechanism in 1-2 sentences, (3) Scope of impact with numbers, (4) Vendor/CERT response status, (5) Strategic significance. Must name-drop every relevant entity. ZERO filler.",
  "risk_assessment": "3-4 sentences: (1) WHO is at risk — name specific products, versions, configurations, (2) Business impact — data loss, ransomware, espionage, supply chain, (3) Exploitability — public PoC, active exploitation, attack complexity. Include quantified risk where possible.",
  "attack_narrative": "4-6 sentences describing the technical attack chain step-by-step. Name specific tools, protocols, and techniques at each stage. Use arrow notation: 'Initial access via X → Dropped Y → C2 over Z → Lateral movement via W → Exfil to Q'.",
  "why_it_matters": ["3-5 SHORT action items. Each starts with a verb: 'Patch...', 'Block...', 'Audit...', 'Hunt for...', 'Escalate if...'. Each MUST name a specific CVE/product/tool/actor. Max 20 words per bullet. NO generic advice."],
  "tags": ["8-12 keywords: CVE IDs, product names, malware names, technique names, affected platforms"],
  "threat_actors": ["Named APT groups with aliases in parens, e.g., 'APT29 (Cozy Bear / Midnight Blizzard)'. Empty [] only if truly unknown."],
  "malware_families": ["Named malware, RATs, loaders, tools. Include dual-use tools (Cobalt Strike, Mimikatz, Impacket). Empty [] only if none involved."],
  "campaign_name": "Named campaign or null",
  "cves": ["CVE-YYYY-NNNNN format. Include CVEs mentioned + any related CVEs you know are chained or co-exploited."],
  "vulnerable_products": ["Product name with version ranges, e.g., 'PAN-OS 10.2.x < 10.2.9-h1', 'Chrome < 123.0.6312.86'. Be specific."],
  "tactics_techniques": ["Format: 'T1234.001 - Technique Name'. Include 3-6 techniques. Map the FULL kill chain, not just initial access."],
  "initial_access_vector": "Specific vector: 'Phishing with ISO attachment', 'Exploitation of internet-facing PAN-OS', 'Supply chain compromise via npm package', or null",
  "post_exploitation": ["Name specific tools & actions: 'LSASS credential dump via Nanodump', 'Lateral movement using WMI and PSExec', 'Data exfiltration to attacker-controlled S3 bucket'. 2-5 items."],
  "targeted_sectors": ["Specific sectors. 'Government — Defense', 'Financial Services — Banking', 'Healthcare — Hospitals'. Always at least 1."],
  "targeted_regions": ["Specific regions. 'South Korea', 'Western Europe', 'United States — Federal'. Always at least 1."],
  "impacted_assets": ["Specific asset types: 'Palo Alto GlobalProtect VPN appliances', 'Chrome browser on Windows/Mac/Linux', 'OAuth tokens in Azure AD'. Not generic 'endpoints'."],
  "ioc_summary": {"domains": [], "ips": [], "hashes": [], "urls": []},
  "timeline": [{"date": "YYYY-MM-DD or null", "event": "description"}],
  "detection_opportunities": ["3-5 items. Each MUST name a log source, query pattern, or signature ID. Examples: 'Sigma rule for regsvr32 loading DLL from user temp folder', 'Snort SID 300125 for CobaltStrike beacon HTTP profile', 'Windows Event 4688 + CommandLine containing certutil -urlcache'. No vague 'monitor for anomalies'."],
  "mitigation_recommendations": ["3-5 items. Each MUST name the specific fix: patch version, config change command, GPO setting, or firewall rule. Example: 'Disable PAN-OS telemetry: set deviceconfig system device-telemetry device-health-performance no', 'Block .iso/.img at email gateway via transport rule'. No generic 'apply patches'."],
  "yara_rule": "A complete, working YARA rule for detecting the malware/threat described. Include: rule name (snake_case reflecting the threat), meta (author='IntelWatch AI', description, date, reference, threat_level), strings section with relevant patterns (file artifacts, registry keys, mutexes, embedded strings, byte patterns from the article), and a condition that combines them logically. If the article is policy/regulation/informational with no detectable artifacts, return null. Example format:\nrule threat_name {\n  meta:\n    author = \"IntelWatch AI\"\n    description = \"Detects ...\"\n    date = \"YYYY-MM-DD\"\n    threat_level = \"high\"\n  strings:\n    $s1 = \"string_pattern\" ascii wide\n    $s2 = { hex pattern }\n  condition:\n    uint16(0) == 0x5A4D and 2 of ($s*)\n}",
  "kql_rule": "A complete, working KQL (Kusto Query Language) detection query for Microsoft Sentinel / Defender XDR. Target the most relevant log table (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, SecurityEvent, SigninLogs, EmailEvents, etc.). Include: comments explaining what is detected, the table name, where/filter clauses with specific IOCs/patterns from the article, project clause selecting relevant columns, optional summarize for aggregation. If no actionable detection is possible, return null. Example format:\n// Detect [threat description]\nDeviceProcessEvents\n| where Timestamp > ago(30d)\n| where ProcessCommandLine has_any (\"pattern1\", \"pattern2\")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n| sort by Timestamp desc",
  "reference_links": ["ONLY URLs that appear VERBATIM in the provided article content. Copy-paste them exactly as they appear in the text. Do NOT invent, guess, or construct URLs — if a URL is not explicitly written in the article, do NOT include it. Return an empty array [] if no URLs are found in the text. The original article URL is added automatically — do not include it."],
  "recommended_priority": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "relevance_score": 50
}

Scoring: 90-100 active zero-day/KEV; 70-89 major breach/APT/ransomware; 50-69 notable vuln/research; 30-49 policy/informational; 1-29 low-impact."""


async def enrich_news_item(headline: str, raw_content: str) -> dict | None:
    """Use AI to extract structured intelligence from a news article."""
    user_prompt = f"Headline: {headline}\n\nContent:\n{raw_content[:10000]}"

    result = await chat_completion(
        system_prompt=_NEWS_ENRICHMENT_SYSTEM,
        user_prompt=user_prompt,
        max_tokens=5000,
        temperature=0.15,
    )

    if not result:
        return None

    # Robust JSON extraction — try multiple strategies
    data = _extract_json(result)
    if data:
        return data

    logger.warning("news_ai_json_parse_error", headline=headline[:80])
    return None


def _extract_json(text: str) -> dict | None:
    """Try multiple strategies to extract JSON from AI response text."""
    text = text.strip()

    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Strip markdown fences (```json ... ```)
    cleaned = re.sub(r"^```(?:json)?\s*", "", text)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Strategy 3: Find first { ... last } (outermost JSON object)
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace:last_brace + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Strategy 4: Try fixing common issues — trailing commas, single quotes
    if first_brace != -1 and last_brace > first_brace:
        candidate = text[first_brace:last_brace + 1]
        # Remove trailing commas before } or ]
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return None
