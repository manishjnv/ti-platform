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
    """Fetch all configured RSS feeds concurrently, then extract full article text."""
    import asyncio
    tasks = [fetch_rss_feed(feed) for feed in NEWS_FEEDS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_articles: list[dict] = []
    for result in results:
        if isinstance(result, list):
            all_articles.extend(result)
        elif isinstance(result, Exception):
            logger.warning("news_feed_exception", error=str(result)[:200])

    logger.info("news_rss_fetched", total=len(all_articles), sources=len(NEWS_FEEDS))

    # Extract full article text (replaces short RSS summaries)
    if all_articles:
        all_articles = list(await _enrich_articles_with_fulltext(all_articles))
        full_count = sum(1 for a in all_articles if len(a.get("raw_content", "")) > 1000)
        logger.info(
            "news_fulltext_done",
            total=len(all_articles),
            full_text=full_count,
        )

    return all_articles


# ── AI Enrichment ────────────────────────────────────────

_NEWS_ENRICHMENT_SYSTEM = """You are a senior cyber threat intelligence analyst at a Fortune 100 SOC. You write for two audiences: a CISO who needs business-impact framing in ≤60 seconds, and a SOC analyst who needs detection rules and IOC-actionable details.

Given a cybersecurity news headline + content, produce a structured JSON intelligence brief.

## QUALITY RULES — READ CAREFULLY

**BANNED PHRASES (never use these — they are meaningless filler):**
- "timely patching is crucial", "apply patches and updates", "keep software up to date"
- "monitor for suspicious/unusual activity", "implement robust security controls"
- "organizations should prioritize security", "stay vigilant"
- Any sentence that could apply to ANY article generically is FILLER — delete it.

**REQUIRED QUALITY: every bullet/sentence must contain at least ONE of:**
- A specific technology, CVE, tool name, or protocol
- A concrete SIEM query, log source, or EDR detection
- A measurable action with a clear owner (e.g., "IAM team should audit OAuth app grants in Entra ID within 48h")
- A named threat group, malware hash, or campaign identifier
- A quantified business impact (dollar amount, number of records, downtime hours)

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
  "summary": "2-3 sentences. Lead with WHAT happened, then WHO is affected, then SO WHAT for defenders.",
  "executive_brief": "6-10 sentences structured as: (1) What happened with specific names/dates, (2) Technical mechanism in 1-2 sentences, (3) Scope of impact with numbers if available, (4) Vendor/CERT response status, (5) What this means strategically for enterprises. NEVER use filler.",
  "risk_assessment": "3-4 sentences: (1) Who is at risk — name specific products, versions, configurations, (2) What is the business impact — data loss, ransomware, espionage, supply chain, (3) Exploitability — is there a public PoC, is it in active exploitation, what is the attack complexity.",
  "attack_narrative": "4-6 sentences describing the technical attack chain step-by-step. Name specific tools, protocols, and techniques at each stage. Example: 'Initial access via spearphish with ISO attachment → Dropped QakBot loader via regsvr32 → C2 over HTTPS to 185.x.x.x → Cobalt Strike beacon deployed → LSASS dumped via Nanodump → Lateral movement via PSExec → Data staged in C:\\ProgramData → Exfil via Rclone to Mega.nz'.",
  "why_it_matters": ["3-5 points. Each MUST contain a specific product, CVE, threshold, or named entity. Start each with a verb: 'Patch...', 'Block...', 'Audit...', 'Hunt for...', 'Escalate if...'. No generic advice."],
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
        max_tokens=3500,
        temperature=0.15,
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
