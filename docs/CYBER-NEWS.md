# IntelWatch — Cyber News Intelligence Module

> Complete technical reference for the Cyber News feature: rules, logic, conditions, thresholds, and future enhancements.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [RSS Feed Sources](#2-rss-feed-sources)
3. [Content Ingestion Pipeline](#3-content-ingestion-pipeline)
4. [Deduplication Engine](#4-deduplication-engine)
5. [Full-Text Extraction](#5-full-text-extraction)
6. [AI Enrichment](#6-ai-enrichment)
7. [Category Detection](#7-category-detection)
8. [Keyword Highlighting Rules](#8-keyword-highlighting-rules)
9. [Report Generation](#9-report-generation)
10. [IOC Search Popup](#10-ioc-search-popup)
11. [API Endpoints](#11-api-endpoints)
12. [Database Schema](#12-database-schema)
13. [Scheduling & Worker Tasks](#13-scheduling--worker-tasks)
14. [Caching Strategy](#14-caching-strategy)
15. [Error Handling & Rate Limiting](#15-error-handling--rate-limiting)
16. [Constants & Thresholds Reference](#16-constants--thresholds-reference)
17. [Future Enhancements](#17-future-enhancements)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         Scheduler                           │
│  ingest_news (every 30 min)  │  enrich_news (every 5 min)  │
│                              │  cleanup_stale (every 6 hr)  │
└──────────────┬───────────────┴──────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────┐       ┌──────────────────────────────┐
│    RSS Feed Fetcher  │       │      AI Enrichment Worker    │
│  19 feeds, 4 tiers   │       │  Groq → Cerebras fallback    │
│  httpx + trafilatura │       │  1s throttle per item         │
│                      │       │  Category enum validation    │
│  ↓ Pre-score 70+     │       └──────────────┬───────────────┘
│    keyword rules     │                      │
│  ↓ Keep top 10/cycle │                      ▼
│    (~15/hour max)    │
└──────────┬───────────┘
           │
           ▼                  UI defaults to ai_enriched=true
┌──────────────────────────────────────────────────────────────┐
│                       PostgreSQL (TimescaleDB)              │
│                     news_items (41 columns)                  │
│  source_hash UNIQUE │ GIN trigram │ partial idx ai_enriched  │
└──────────────────────────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     FastAPI Routes (/news)                   │
│  List │ Detail │ Categories │ Report (PDF/HTML/MD) │ Refresh │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                      Next.js Frontend                        │
│  News List │ Detail Page │ Keyword Highlights │ IOC Popup    │
│  Report Format Dropdown │ Category Filtering │ Tag Search    │
└──────────────────────────────────────────────────────────────┘
```

**Data flow:** RSS feeds → parse + dedup → store → AI enrich → serve via API → render in UI with interactive highlights.

---

## 2. RSS Feed Sources

20 feeds organized into 4 quality/trust tiers.

### Tier 1 — Major Security News

| Source | Feed URL | Default Category |
|--------|----------|------------------|
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` | `active_threats` |
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` | `active_threats` |
| Krebs on Security | `https://krebsonsecurity.com/feed/` | `ransomware_breaches` |
| Dark Reading | `https://www.darkreading.com/rss.xml` | `security_research` |
| SecurityWeek | `https://feeds.feedburner.com/securityweek` | `active_threats` |
| The Record | `https://therecord.media/feed` | `nation_state` |
| CyberScoop | `https://cyberscoop.com/feed/` | `nation_state` |

### Tier 2 — Government / CERT Advisories

| Source | Feed URL | Default Category |
|--------|----------|------------------|
| CISA Alerts | `https://www.cisa.gov/cybersecurity-advisories/all.xml` | `exploited_vulnerabilities` |

### Tier 3 — Vendor Threat Research Blogs

| Source | Feed URL | Default Category |
|--------|----------|------------------|
| Microsoft Security | `https://www.microsoft.com/en-us/security/blog/feed/` | `security_research` |
| Google TAG | `https://blog.google/threat-analysis-group/rss/` | `nation_state` |
| Cisco Talos | `https://blog.talosintelligence.com/rss/` | `security_research` |
| SentinelOne Labs | `https://www.sentinelone.com/labs/feed/` | `security_research` |
| Unit 42 | `https://unit42.paloaltonetworks.com/feed/` | `security_research` |
| Sophos News | `https://news.sophos.com/en-us/category/threat-research/feed/` | `active_threats` |
| WeLiveSecurity | `https://www.welivesecurity.com/en/rss/feed/` | `security_research` |
| Mandiant | `https://www.mandiant.com/resources/blog/rss.xml` | `nation_state` |

### Tier 4 — Expert / Independent

| Source | Feed URL | Default Category |
|--------|----------|------------------|
| Schneier on Security | `https://www.schneier.com/blog/atom.xml` | `policy_regulation` |
| Graham Cluley | `https://grahamcluley.com/feed/` | `active_threats` |
| Threatpost | `https://threatpost.com/feed/` | `active_threats` |

### Feed Configuration Rules

- Each feed defines: `name`, `url`, `default_category`
- Category is a hint; AI enrichment will reclassify based on content analysis
- Feeds that return HTTP errors are logged and skipped; they don't block other feeds
- Feed fetching uses `httpx.AsyncClient` with **20-second timeout**

---

## 3. Content Ingestion Pipeline

### Step-by-Step Flow

```
1. Fetch all 19 RSS feeds in parallel (asyncio.gather, return_exceptions=True)
2. Parse each feed → extract articles (title, link, published, description)
3. Compute source_hash = SHA-256("{feed_name}:{article_url}")
4. ★ PRE-SCORE every article by headline relevance (see §3.1)
5. ★ RANK by pre-score + recency, keep only TOP 10 per cycle (~15/hr)
6. Full-text extraction via trafilatura (only for kept articles)
7. Level 1 dedup: Skip if source_hash already in DB
8. Level 2 dedup: Cross-source headline similarity check (see §4)
9. If duplicate found → merge content (see §4.3)
10. Store in news_items table
11. Queue for AI enrichment (next scheduler cycle, 5-min interval)
12. UI shows ONLY ai_enriched=true articles by default
```

### 3.1 Headline Relevance Pre-Scorer

Before storing, every fetched article receives a **pre-score** based on
headline + first 2000 chars of content. Only the top `MAX_ARTICLES_PER_CYCLE`
(default: **10**) articles are kept per ingestion cycle.

#### High-Value Keywords (additive scoring)

| Category | Keywords (subset) | Points |
|----------|-------------------|--------|
| Active exploitation / zero-day | `zero-day`, `0-day`, `actively exploited`, `in the wild`, `kev`, `cisa adds` | +25 |
| CVEs / vulnerabilities | `cve-`, `critical vulnerability`, `rce`, `remote code execution`, `privilege escalation` | +20 |
| Named threat actors / APTs | `lazarus`, `cozy bear`, `fancy bear`, `volt typhoon`, `scattered spider`, `lockbit`, `alphv` … (18 groups) | +20 |
| Ransomware / major breaches | `ransomware`, `data breach`, `million records`, `extortion`, `leaked` | +18 |
| Malware families | `malware`, `trojan`, `backdoor`, `rootkit`, `infostealer`, `cobalt strike` | +15 |
| Government / nation-state | `nation-state`, `espionage`, `cyber command`, `nsa`, `fbi`, `cisa`, `sanctions` | +15 |
| Supply chain | `supply chain`, `npm`, `pypi`, `solarwinds`, `moveit` | +15 |
| Tactical content | `ioc`, `sigma rule`, `yara`, `snort`, `suricata`, `detection`, `hunting` | +12 |
| Major vendors | `microsoft`, `google`, `apple`, `cisco`, `palo alto`, `fortinet`, `crowdstrike` … | +10 |
| Cloud / identity | `azure`, `aws`, `gcp`, `entra`, `oauth`, `saml`, `sso` | +10 |

#### Low-Value Penalties (subtractive)

| Pattern | Keywords | Penalty |
|---------|----------|---------|
| Marketing | `podcast`, `webinar`, `register now`, `sponsored` | -30 |
| Jobs | `job opening`, `career`, `hiring`, `salary` | -30 |
| Product launches | `product launch`, `new feature`, `announces partnership` | -15 |
| Editorial | `opinion:`, `editorial`, `book review`, `interview with` | -10 |

#### Source Tier Bonuses

| Tier | Sources | Bonus |
|------|---------|-------|
| Tier 1 – Breaking News | BleepingComputer, The Hacker News, Krebs, The Record | +10–12 |
| Tier 2 – Government | CISA Alerts | +15 |
| Tier 3 – Vendor Research | Google TAG, Mandiant, Unit 42, Microsoft Security | +10–12 |
| Tier 4 – Independent | Schneier, Graham Cluley, Threatpost | +5–6 |

#### Recency Bonuses

| Age | Bonus |
|-----|-------|
| < 6 hours | +10 |
| 6–24 hours | +5 |
| > 24 hours | +0 |

### HTML Stripping

RSS `<description>` content is cleaned before storage:

```python
re.sub(r"<[^>]+>", " ", html)          # strip HTML tags
re.sub(r"&[a-z]+;", " ", text)         # strip HTML entities
re.sub(r"\s+", " ", text).strip()      # normalize whitespace
```

Cap: **12,000 characters** after stripping.

### Source Hash Calculation

```python
source_hash = SHA-256("{feed_name}:{article_url}")
```

- Stored as `VARCHAR(64)` with a UNIQUE index
- Guarantees exact-URL dedup within the same feed source

---

## 4. Deduplication Engine

Three-level dedup prevents duplicates and merges cross-source coverage.

### 4.1 Level 1 — Exact Source Hash

**Condition:** `source_hash` already exists in DB → **skip entirely**.

This catches re-ingestion of the same article URL from the same feed.

### 4.2 Level 2 — Cross-Source Headline Similarity

When a new article passes Level 1, its headline is compared against all articles from the **last 48 hours** (different sources only).

#### Tokenization

```python
re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", headline.lower())
```

- Extracts lowercase alphanumeric tokens including hyphenated words (e.g., `zero-day`)

#### Stop Word Removal

40 stop words removed:

```
the, a, an, and, or, but, in, on, at, to, for, of, with, by, from, up, about,
into, through, during, before, after, above, below, between, out, off, over,
under, again, further, then, once, is, are, was, were, be, been, being, have
```

#### Stemming (Suffix Stripping)

Simple suffix removal with **minimum stem length of 3 characters**:

Suffixes removed (in order): `ting`, `ing`, `ied`, `ies`, `ity`, `ness`, `ment`, `ous`, `ive`, `able`, `ble`, `ful`, `less`, `ated`, `ates`, `tion`, `sion`, `ed`, `es`, `ly`, `er`, `al`, `en`

Additionally, trailing `s` is stripped if stem length > 3.

**Exceptions kept intact:**
- CVE IDs: tokens matching `^cve-\d{4}-\d+$`
- Pure numbers: tokens matching `^\d+$`

#### Similarity Algorithm

**Jaccard Similarity:**

```
similarity = |A ∩ B| / |A ∪ B|
```

Where A and B are sets of stemmed tokens.

#### CVE Boost Rule

If both headlines share at least one CVE ID (token starting with `cve-`):

```
similarity = max(0.80, jaccard_similarity)
```

This guarantees articles about the same CVE are grouped together, even if headlines differ substantially.

#### Threshold

```python
DUPLICATE_SIMILARITY_THRESHOLD = 0.40  # ≥40% token overlap = same story
```

**Cross-source only:** Same-source articles are never compared against each other (they're handled by Level 1).

### 4.3 Level 3 — Content Merge on Duplicate

When Level 2 detects a cross-source duplicate:

**Merge conditions (both must be true):**
- New article's content > **500 characters**
- New content is > **30%** of existing article's content length

**Merge behavior:**
1. Append new content with separator: `"--- Additional coverage from {source} ---"`
2. Cap merged content at **15,000 characters**
3. Add to `correlated_sources` JSONB: `{source, url, headline[:200]}`
4. If existing article was already AI-enriched, reset `ai_enriched = False` to re-queue enrichment with richer merged content

---

## 5. Full-Text Extraction

### Library

**trafilatura** — extracts main article content from HTML, removing navigation, ads, and boilerplate.

### Configuration

| Parameter | Value |
|-----------|-------|
| Library | `trafilatura` |
| `include_comments` | `False` |
| `include_tables` | `False` |
| `no_fallback` | `False` |
| HTTP timeout | **15 seconds** |
| Follow redirects | `True` |
| Max concurrency | **10** (asyncio Semaphore) |
| Output cap | **12,000 characters** |
| Minimum length | **200 characters** (below = discard, keep RSS summary) |

### User-Agent

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
```

### Fallback

If trafilatura extraction fails, returns < 200 chars, or HTTP error occurs, the article falls back to using the RSS `<description>` field content.

---

## 6. AI Enrichment

### 6.1 Provider Fallback Chain

Five providers tried in order until one succeeds:

| Priority | Provider ID | Model | API URL | Timeout | Condition |
|----------|-------------|-------|---------|---------|-----------|
| 1 | `groq-primary` | `llama-3.3-70b-versatile` | `api.groq.com` | 30s | `ai_api_key` set |
| 2 | `groq-llama3.1-8b` | `llama-3.1-8b-instant` | `api.groq.com` | 30s | Same key |
| 3 | `cerebras` | `llama3.1-8b` | `api.cerebras.ai` | 60s | `cerebras_api_key` set |
| 4 | `groq-qwen3` | `qwen/qwen3-32b` | `api.groq.com` | 30s | Same key |
| 5 | `huggingface` | `mistralai/Mistral-7B-Instruct-v0.3` | HuggingFace Inference API | 60s | `hf_api_key` set |

**Fallback triggers:** HTTP 429 (rate limit), 503 (overloaded), 403 (forbidden), timeout → cascade to next provider.

### 6.2 News AI Call Parameters

| Parameter | Value |
|-----------|-------|
| Function | `enrich_news_item(headline, raw_content)` |
| max_tokens | **3,500** |
| temperature | **0.15** |
| User prompt input cap | **10,000 characters** |
| Output parsing | Strip markdown ```json fences, parse as JSON |

### 6.3 System Prompt Rules

The AI is instructed to act as a **Fortune 100 SOC analyst** with specific quality constraints.

#### Banned Phrases

The AI must **never** use these generic phrases:

- "timely patching is crucial"
- "apply patches and updates"
- "keep software up to date"
- "monitor for suspicious activity"
- "implement robust security controls"
- "organizations should prioritize security"
- "stay vigilant"

#### Required Specificity

Every bullet in `why_it_matters`, `detection_opportunities`, and `mitigation_recommendations` must contain at least **ONE** of:

- Specific technology, CVE, or tool name
- SIEM query, log source, or EDR detection logic
- Measurable action with owner role
- Named threat group, hash, or campaign identifier
- Quantified business impact (dollar, user count, record count)

#### Quality Examples (from system prompt)

**BAD (rejected):**
> "Organizations should apply patches promptly"

**GOOD (accepted):**
> "Apply Microsoft KB5034441 to Server 2019/2022 within 72h; SOC verify via SCCM compliance report targeting CVE-2024-21338 kernel LPE"

### 6.4 AI Output Schema (28 fields)

```json
{
  "category": "news_category enum value",
  "summary": "2-3 sentence executive summary",
  "executive_brief": "paragraph for non-technical leadership",
  "risk_assessment": "business risk analysis",
  "attack_narrative": "kill-chain narrative",
  "why_it_matters": ["actionable bullet 1", "bullet 2", ...],
  "tags": ["tag1", "tag2", ...],
  "threat_actors": ["APT28", ...],
  "malware_families": ["Cobalt Strike", ...],
  "campaign_name": "string or null",
  "cves": ["CVE-2024-1234", ...],
  "vulnerable_products": ["Microsoft Exchange 2019", ...],
  "tactics_techniques": ["T1566 - Phishing", "T1059.001 - PowerShell", ...],
  "initial_access_vector": "string or null",
  "post_exploitation": ["bullet 1", ...],
  "targeted_sectors": ["Financial Services", ...],
  "targeted_regions": ["North America", ...],
  "impacted_assets": ["Active Directory", ...],
  "ioc_summary": {
    "domains": ["evil.com"],
    "ips": ["1.2.3.4"],
    "hashes": ["abc123..."],
    "urls": ["http://evil.com/payload"]
  },
  "timeline": [{"date": "2024-01-15", "event": "Initial exploitation observed"}],
  "detection_opportunities": ["Check Sysmon EventID 1 for...", ...],
  "mitigation_recommendations": ["Apply KB5034441 within 72h...", ...],
  "recommended_priority": "critical|high|medium|low",
  "confidence": "high|medium|low",
  "relevance_score": 85
}
```

### 6.5 Relevance Scoring Guide

| Score | Criteria |
|-------|----------|
| 90–100 | Active zero-day exploit, KEV-listed, widespread active exploitation |
| 70–89 | Major breach, APT campaign, ransomware wave, high-profile incident |
| 50–69 | Notable vulnerability, security research, tool release |
| 30–49 | Policy update, regulatory change, informational advisory |
| 1–29 | Low-impact, niche, or historical context |

### 6.6 Enrichment Throttling

- **20-second sleep** between each item enrichment
- Reason: Groq free tier = **6,000 tokens per minute** per model
- Each news enrichment prompt ≈ **4,500 tokens**
- Default batch size from scheduler: **5 items** per cycle (every 5 min)

---

## 7. Category Detection

### Keyword-Based Category Inference

Used during RSS ingestion to assign an initial category before AI reclassification:

| Category | Trigger Keywords |
|----------|-----------------|
| `ransomware_breaches` | ransomware, breach, leak, stolen data, extortion |
| `exploited_vulnerabilities` | exploit, vulnerability, cve-, zero-day, 0-day, patch, kev |
| `nation_state` | apt, nation-state, nation state, china, russia, iran, north korea, espionage |
| `cloud_identity` | cloud, saas, azure, aws, identity, oauth, sso, credential |
| `ot_ics` | ics, ot (with trailing space), scada, plc, industrial, operational technology |
| `tools_technology` | tool, framework, open source, github, release, platform |
| `policy_regulation` | policy, regulation, compliance, gdpr, law, legislation, executive order |
| `security_research` | research, analysis, report, study, paper, findings |
| **Fallback** | `active_threats` |

**Logic:** First matching category wins (checked in order above). Applied to combined `headline + description` (lowercase). AI enrichment may override this with a more accurate classification.

### Category Enum Values (9 categories)

```
active_threats, exploited_vulnerabilities, ransomware_breaches, nation_state,
cloud_identity, ot_ics, security_research, tools_technology, policy_regulation
```

---

## 8. Keyword Highlighting Rules

### 8.1 UI Highlights (News Detail Page)

15 regex rules applied in order. First non-overlapping match wins at each position.

| # | What | Regex | Color | Clickable → IOC Popup |
|---|------|-------|-------|----------------------|
| 1 | CVE IDs | `/\bCVE-\d{4}-\d{4,}\b/g` | orange-400 | **Yes** |
| 2 | MITRE ATT&CK | `/\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b/g` | blue-400 | **Yes** |
| 3 | IP Addresses | `/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g` | sky-400, monospace | **Yes** |
| 4 | SHA-256 | `/\b[a-f0-9]{64}\b/gi` | purple-400, monospace | **Yes** |
| 5 | SHA-1 | `/\b[a-f0-9]{40}\b/gi` | purple-400, monospace | **Yes** |
| 6 | MD5 | `/\b[a-f0-9]{32}\b/gi` | purple-400, monospace | **Yes** |
| 7 | Threat Actors | APT/UNC/FIN groups + named actors | purple-400, bold | **Yes** |
| 8 | Version Numbers | `/\bv?\d+\.\d+(?:\.\d+)+\b/g` | teal-400, monospace | No |
| 9 | File Paths | Unix (`/path/to/file`) or Windows (`C:\path\to\file`) | amber-300, monospace | **Yes** |
| 10 | ISO Dates | `/\b\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b/g` | indigo-400 | No |
| 11 | CVSS Scores | `/\b(?:CVSS[:\s]*)?\d{1,2}\.\d\/10\b/gi` | red-400, bold | No |
| 12 | Action Verbs | patch, update, upgrade, block, disable, revoke, rotate, deploy, scan, isolate, remediate, mitigate/mitigation, harden, restrict, enforce, audit, verify, review, monitor, detect, enable | green-400 | No |
| 13 | Threat Terms | zero-day, critical, exploit(ed/ation/s), ransomware, malware, backdoor, RCE, remote code execution, privilege escalation, data breach/exfiltration/leak, supply-chain, APT, brute-force, phishing, trojan, rootkit, C2, command-and-control, lateral movement | amber-400 | No |
| 14 | Quoted Terms | `/"([^"]{2,40})"/g` (product names, tool names in quotes) | foreground/90 | **Yes** |

#### Known Threat Actor Names (Rule #7)

```
APT\d+, UNC\d+, UAT-\d+, FIN\d+, Lazarus, Fancy Bear, Cozy Bear,
Turla, Sandworm, Kimsuky, ScarCruft, Volt Typhoon, Storm-\d+,
Midnight Blizzard, Scattered Spider
```

#### Overlap Resolution

- All matches are sorted by `start` position
- If a match starts within a previous match's end, it is skipped
- This ensures no double-highlighting on overlapping patterns

#### Click Behavior

- Searchable keywords rendered as `<button>` elements
- `onClick` → opens `IOCSearchPopup` modal with the keyword as query
- Quoted terms have surrounding quotes stripped for the search query

### 8.2 HTML Report Highlights

6 regex-based highlight rules applied to HTML report content:

| Pattern | CSS Class | Color |
|---------|-----------|-------|
| CVE-YYYY-NNNNN | `.kw-cve` | orange, background |
| MITRE T-codes | `.kw-mitre` | blue, background |
| IPv4 addresses | `.kw-ip` | sky, monospace |
| MD5/SHA-1/SHA-256 | `.kw-hash` | purple, monospace |
| APT group names | `.kw-ta` | purple, bold |
| ISO dates | `.kw-date` | accent color |

---

## 9. Report Generation

Three export formats, all from the same `/news/{id}/report?format=` endpoint.

### 9.1 Markdown Report

- TLP:GREEN classification header
- Metadata table: source, category, priority, published date, relevance, confidence, campaign
- Sections (in order): Executive Summary, Intelligence Brief, Risk Assessment, Attack Narrative, Key Takeaways, Threat Landscape, MITRE ATT&CK, Post-Exploitation, Targeting, IOC Table, Timeline, Detection, Mitigation, Tags
- Footer with source URL and auto-generation disclaimer

### 9.2 HTML Report

- **Self-contained** (no external dependencies, inline CSS)
- Dark theme: `--bg: #0a0a0f`, `--surface: #12121a`
- Keyword highlighting via regex (6 rules, see §8.2)
- Grid layout: Risk Assessment + Attack Narrative rendered side-by-side
- IOC table with monospace values and type labels
- Timeline: vertical dot-and-line CSS design
- `@media print` stylesheet: switches to white background for printing
- Max width: 900px container

### 9.3 PDF Report

- Generated with **ReportLab** (`SimpleDocTemplate`, A4 page size)
- Margins: 20mm on all sides
- Typography: Helvetica (body), Helvetica-Bold (headers), Courier (IOC values)
- Font sizes: Title 15px, H2 11px, Body 9px, Bullets 9px (12px indent), Small 8px, Tags 8px
- Inline formatting: CVEs rendered in bold, IPs in blue
- IOC table: header row with #f0f0f5 background, 0.5pt grid lines
- Classification banner: TLP:GREEN in green text, centered
- Meta info: 4-column table (Category/Source/Priority/Published/Relevance/Confidence)

### Priority Labels in Reports

| Priority | Label |
|----------|-------|
| critical | CRITICAL — Immediate action required |
| high | HIGH — Action within 24 hours |
| medium | MEDIUM — Action within 1 week |
| low | LOW — Informational / no immediate action |

---

## 10. IOC Search Popup

### Trigger

Clicking any **searchable** highlighted keyword in the news detail page.

### API

`POST /search/live-lookup` via `api.liveLookup(query)` — queries multiple intelligence sources with AI-powered analysis.

### Behavior

| Feature | Detail |
|---------|--------|
| Auto-search | Fires search on mount with clicked keyword |
| Auto-focus | Input text selected for easy re-query |
| Close methods | `Escape` key, backdrop click, X button |
| Results display | Query metadata, AI summary (indigo card), key findings, remediation, result cards |
| Severity colors | critical=red, high=orange, medium=yellow, low=green, info=blue |
| Footer link | "Open in full search" → `/search?q=...` |
| Error display | Red alert for failed searches |

### Result Card Structure

Each result shows:
- Title (truncated), source + type metadata
- Severity badge (color-coded) + risk score
- Description (2-line clamp)

---

## 11. API Endpoints

### Routes

| Method | Path | Auth | Cache | Description |
|--------|------|------|-------|-------------|
| `GET` | `/news` | `require_viewer` | 60s | Paginated list with filters |
| `GET` | `/news/categories` | `require_viewer` | 60s | Per-category counts + latest headline |
| `GET` | `/news/{id}` | `require_viewer` | 120s | Full detail for single item |
| `GET` | `/news/{id}/report` | `require_viewer` | — | Generate PDF/HTML/Markdown report |
| `POST` | `/news/refresh` | `require_viewer` | — | Manual feed refresh via RQ worker |

### List Endpoint Query Parameters

| Parameter | Type | Default | Constraints |
|-----------|------|---------|-------------|
| `page` | int | 1 | `≥1` |
| `page_size` | int | 20 | `1–100` |
| `category` | string | — | Optional, must be valid `news_category` |
| `tag` | string | — | Optional, matched via `ANY(tags)` |
| `search` | string | — | Optional, max 200 chars, ILIKE on headline + summary |
| `min_relevance` | int | — | Optional, `0–100` |
| `ai_enriched` | bool | — | Optional filter |
| `sort_by` | string | `published_at` | `published_at`, `relevance_score`, `created_at` |
| `sort_order` | string | `desc` | `asc`, `desc` |

### Report Endpoint Query Parameter

| Parameter | Type | Default | Values |
|-----------|------|---------|--------|
| `format` | string | `pdf` | `pdf`, `html`, `markdown` |

---

## 12. Database Schema

### Table: `news_items` (41 columns)

#### Core Fields

| Column | Type | Nullable | Default | Notes |
|--------|------|----------|---------|-------|
| `id` | UUID | No | `gen_random_uuid()` | Primary key |
| `headline` | TEXT | No | | Article title |
| `source` | VARCHAR(200) | No | | Feed source name |
| `source_url` | TEXT | No | | Original article URL |
| `published_at` | TIMESTAMPTZ | Yes | | From RSS feed |
| `category` | `news_category` enum | No | `active_threats` | 9 categories |
| `raw_content` | TEXT | Yes | | Full article text |
| `source_hash` | VARCHAR(64) | No | | SHA-256 dedup key |
| `correlated_sources` | JSONB | No | `'[]'` | Cross-source tracking |
| `ai_enriched` | BOOLEAN | No | `FALSE` | Enrichment status |
| `created_at` | TIMESTAMPTZ | No | `NOW()` | |
| `updated_at` | TIMESTAMPTZ | No | `NOW()` | |

#### AI-Generated Intelligence Fields

| Column | Type | Default |
|--------|------|---------|
| `summary` | TEXT | NULL |
| `executive_brief` | TEXT | NULL |
| `risk_assessment` | TEXT | NULL |
| `attack_narrative` | TEXT | NULL |
| `why_it_matters` | TEXT[] | `{}` |
| `tags` | TEXT[] | `{}` |
| `threat_actors` | TEXT[] | `{}` |
| `malware_families` | TEXT[] | `{}` |
| `campaign_name` | VARCHAR(300) | NULL |
| `cves` | TEXT[] | `{}` |
| `vulnerable_products` | TEXT[] | `{}` |
| `tactics_techniques` | TEXT[] | `{}` |
| `initial_access_vector` | TEXT | NULL |
| `post_exploitation` | TEXT[] | `{}` |
| `targeted_sectors` | TEXT[] | `{}` |
| `targeted_regions` | TEXT[] | `{}` |
| `impacted_assets` | TEXT[] | `{}` |
| `ioc_summary` | JSONB | `'{}'` |
| `timeline` | JSONB | `'[]'` |
| `detection_opportunities` | TEXT[] | `{}` |
| `mitigation_recommendations` | TEXT[] | `{}` |
| `recommended_priority` | VARCHAR(20) | `'medium'` |
| `confidence` | `confidence_level` enum | `'medium'` |
| `relevance_score` | SMALLINT | `50` |

#### Indexes (8)

| Index | Type | Expression | Purpose |
|-------|------|-----------|---------|
| `idx_news_source_hash` | UNIQUE B-tree | `source_hash` | Exact dedup |
| `idx_news_category` | B-tree | `(category, published_at DESC)` | Category listing |
| `idx_news_published` | B-tree | `published_at DESC` | Chronological sort |
| `idx_news_relevance` | B-tree | `(relevance_score DESC, published_at DESC)` | Top-relevance queries |
| `idx_news_tags` | GIN | `tags` | Tag search |
| `idx_news_cves` | GIN | `cves` | CVE lookup |
| `idx_news_headline_trgm` | GIN trigram | `headline gin_trgm_ops` | Fuzzy headline search |
| `idx_news_ai_enriched` | Partial B-tree | `ai_enriched WHERE ai_enriched = FALSE` | Enrichment queue |

#### ENUM Types

```sql
CREATE TYPE news_category AS ENUM (
  'active_threats', 'exploited_vulnerabilities', 'ransomware_breaches',
  'nation_state', 'cloud_identity', 'ot_ics',
  'security_research', 'tools_technology', 'policy_regulation'
);

CREATE TYPE confidence_level AS ENUM ('high', 'medium', 'low');
```

---

## 13. Scheduling & Worker Tasks

### Scheduler Configuration

| Task | Function | Interval | Queue | Delay Offset | Parameters |
|------|----------|----------|-------|-------------|------------|
| News Ingestion | `worker.tasks.ingest_news` | **30 min** | `default` | +2 min | Top 10 per cycle |
| News Enrichment | `worker.tasks.enrich_news_batch` | **5 min** | `low` | +4 min | `batch_size=5` |
| Stale News Cleanup | `worker.tasks.cleanup_stale_news` | **6 hours** | `low` | +10 min | `max_age_hours=6` |

### Scheduler Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `EXPECTED_JOB_COUNT` | 22 | Total scheduled jobs across all features |
| `MAX_ARTICLES_PER_CYCLE` | 10 | Max articles stored per ingestion cycle |
| `WATCHDOG_INTERVAL` | 120s | Job health check interval |
| `HEARTBEAT_KEY` | `scheduler:heartbeat` | Redis key for heartbeat |
| `HEARTBEAT_TTL` | 300s | Heartbeat expiry |

### Worker Task: `ingest_news`

1. Fetch all RSS feeds (parallel, 20s timeout per feed)
2. Parse entries, compute source hashes
3. **Pre-score every article** (headline + content keywords)
4. **Sort by score descending, keep top 10** (drops hundreds of low-value items)
5. Extract full-text for kept articles only (saves bandwidth)
6. Load existing hashes from DB (batch query)
7. Load last 48h headlines for cross-source dedup
8. For each article: dedup → store
9. Log ingestion stats (fetched, stored, merged, dropped)

### Worker Task: `enrich_news_batch(batch_size=5)`

1. Query `WHERE ai_enriched = FALSE ORDER BY created_at ASC LIMIT batch_size`
2. For each item:
   a. Call `enrich_news_item(headline, raw_content[:10000])`
   b. **Validate category** against enum (`_normalize_category` with 27-entry fallback map)
   c. **Validate confidence** against enum (`high|medium|low`)
   d. Parse JSON response, update all 28 enrichment columns
   e. `session.flush()` per item — one bad item doesn't crash batch
   f. Set `ai_enriched = True`
   g. Sleep **1 second** (Cerebras doesn't need long throttle)
3. If AI returns `None`, item stays unenriched for next cycle
4. Per-item try/except with rollback isolates failures

### Worker Task: `cleanup_stale_news(max_age_hours=6)`

1. Find unenriched items older than `max_age_hours`
2. DELETE them — stale content replaced by fresher articles next cycle
3. Runs every **6 hours**

### Category Validation

AI models sometimes return invalid categories (e.g., `security_operations`).
The `_normalize_category()` function:

1. Check if value is in `_VALID_NEWS_CATEGORIES` set (9 valid values)
2. If not, look up `_CATEGORY_FALLBACK_MAP` (27 common hallucinated categories)
3. If no mapping found, use item's existing category or default `active_threats`

---

## 14. Caching Strategy

| Cache Key Pattern | TTL | Scope |
|-------------------|-----|-------|
| `news_list:{page}:{page_size}:{filter_hash}` | 60s | Paginated list with all filter combinations |
| `news_categories` | 60s | Category counts and latest headlines |
| `news_detail:{uuid}` | 120s | Individual news item |
| `ai_summary:{title}:{severity}` | 3600s | AI summaries for intel items (shared) |

All caching uses Redis via the app's `set_cached`/`get_cached` utility.

---

## 15. Error Handling & Rate Limiting

### RSS Feed Errors

- `httpx.TimeoutException` → warning log, return empty list for that feed
- Generic `Exception` → warning log (error truncated to 200 chars), return empty
- Individual feed failures **do not block** other feeds (`return_exceptions=True`)

### Full-Text Extraction Errors

- HTTP errors → fall back to RSS description
- Extraction returns < 200 chars → discard, use RSS description
- `trafilatura` crash → caught, RSS description used

### AI Provider Errors

| HTTP Status | Action |
|-------------|--------|
| 429 (Rate Limited) | Try next provider |
| 503 (Overloaded) | Try next provider |
| 403 (Forbidden) | Try next provider |
| Timeout | Try next provider |
| All providers fail | Return `None`, item stays unenriched |

### API Validation

| Error Condition | Response |
|-----------------|----------|
| News item not found | `404 Not Found` |
| Invalid `sort_by` / `sort_order` / `format` | FastAPI pattern validation (422) |
| `min_relevance` out of 0–100 | FastAPI constraint validation (422) |
| `search` > 200 chars | FastAPI constraint validation (422) |

### Rate Limiting

- **AI enrichment:** 1-second pause between items (Cerebras primary, Groq fallback)
- **Full-text extraction:** Semaphore(10) concurrent fetches max
- **Event loop reuse:** `_run_async()` reuses event loop per-thread via `threading.local()` to prevent "Event loop is closed" errors
- **No API rate limiting** on news endpoints themselves (protected by auth only)

---

## 16. Constants & Thresholds Reference

Quick-reference table of every configurable value:

| Constant | Value | Location | Category |
|----------|-------|----------|----------|
| RSS feed count | 20 | `services/news.py` | Feeds |
| RSS fetch timeout | 20s | `services/news.py` | Feeds |
| Full-text fetch timeout | 15s | `services/news.py` | Extraction |
| Full-text max concurrency | 10 | `services/news.py` | Extraction |
| Full-text output cap | 12,000 chars | `services/news.py` | Extraction |
| Full-text min length | 200 chars | `services/news.py` | Extraction |
| RSS content cap (after HTML strip) | 12,000 chars | `services/news.py` | Ingestion |
| Dedup similarity threshold | 0.40 (40%) | `services/news.py` | Dedup |
| CVE boost floor | 0.80 | `services/news.py` | Dedup |
| Cross-source dedup window | 48 hours | `worker/tasks.py` | Dedup |
| Merge min content | 500 chars | `worker/tasks.py` | Dedup |
| Merge min content ratio | 30% | `worker/tasks.py` | Dedup |
| Merged content cap | 15,000 chars | `worker/tasks.py` | Dedup |
| Stop words count | 40 | `services/news.py` | Dedup |
| Stem suffixes count | 22 | `services/news.py` | Dedup |
| Min stem length | 3 chars | `services/news.py` | Dedup |
| AI input cap | 10,000 chars | `services/news.py` | AI |
| AI max_tokens | 3,500 | `services/news.py` | AI |
| AI temperature | 0.15 | `services/news.py` | AI |
| AI provider count | 5 | `services/ai.py` | AI |
| AI primary timeout | 30s | `core/config.py` | AI |
| AI enrichment throttle | 1s | `worker/tasks.py` | AI |
| Enrichment batch size (scheduler) | 5 | `worker/scheduler.py` | Scheduling |
| Ingestion interval | 30 min | `worker/scheduler.py` | Scheduling |
| Enrichment interval | 5 min | `worker/scheduler.py` | Scheduling |
| Cleanup interval | 6 hours | `worker/scheduler.py` | Scheduling |
| Stale news max age | 6 hours | `worker/tasks.py` | Scheduling |
| Max articles per cycle | 10 | `services/news.py` | Ingestion |
| Pre-score keyword categories | 10 | `services/news.py` | Ingestion |
| Source tier bonuses | 19 sources | `services/news.py` | Ingestion |
| Low-value penalty rules | 4 categories | `services/news.py` | Ingestion |
| Category validation map | 27 entries | `worker/tasks.py` | Validation |
| Valid news categories | 9 | `models/models.py` | Validation |
| Default relevance_score | 50 | `worker/tasks.py` | Defaults |
| Default confidence | medium | `worker/tasks.py` | Defaults |
| Default priority | medium | DB schema | Defaults |
| List cache TTL | 60s | `routes/news.py` | Caching |
| Categories cache TTL | 60s | `routes/news.py` | Caching |
| Detail cache TTL | 120s | `routes/news.py` | Caching |
| AI summary cache TTL | 3600s | `services/ai.py` | Caching |
| Default page_size | 20 | `routes/news.py` | API |
| Max page_size | 100 | `routes/news.py` | API |
| Search max_length | 200 | `routes/news.py` | API |
| Report filename cap | 60 chars | `routes/news.py` | Reports |
| UI highlight rules | 15 | News detail page | UI |
| UI searchable rules | 9 | News detail page | UI |

---

## 17. Future Enhancements

### 17.1 Feed Expansion

- **Industry-specific feeds:** ICS-CERT, SANS ISC, FS-ISAC, Health-ISAC
- **Regional feeds:** JP-CERT, CERT-EU, AusCERT, BSI (Germany)
- **Social media ingestion:** X/Twitter threat intel accounts, Reddit r/netsec
- **Dark web monitoring:** Integrate paste-site scrapers (e.g., IntelX, PasteBin)
- **GitHub Security Advisories:** GHSA feed for open-source vulns
- **Dynamic feed management:** Admin UI to add/remove/enable/disable feeds without code changes

### 17.2 Deduplication Improvements

- **TF-IDF or sentence embeddings:** Replace Jaccard with semantic similarity (e.g., sentence-transformers) for better cross-source matching
- **Configurable threshold:** Admin setting for similarity threshold (currently hardcoded 0.40)
- **Topic clustering:** Group related (but not duplicate) articles into story threads
- **Dedup dashboard:** Show admin stats on duplicates caught, merge events, false positives
- **Cross-day dedup:** Extend beyond 48h window for long-running stories

### 17.3 AI Enrichment

- **Local model fallback:** Run a local LLM (e.g., Ollama with Llama 3.1 8B) when all cloud providers fail
- **Confidence auto-adjustment:** Re-score confidence based on number of correlated sources
- **Incremental enrichment:** Update only changed fields when re-enriching merged articles
- **STIX/TAXII output:** Generate STIX 2.1 bundles from enrichment data
- **IOC auto-extraction (regex fallback):** Extract IOCs from raw_content directly when AI is unavailable
- **Human-in-the-loop:** Allow analysts to correct/override AI classifications, feed corrections back as training signal
- **Multi-language support:** Translate non-English articles before enrichment

### 17.4 Content Extraction

- **JavaScript rendering:** Use Playwright/Puppeteer for JS-heavy sites where trafilatura fails
- **PDF ingestion:** Extract text from PDF advisories (e.g., CISA ICS advisories)
- **Image OCR:** Extract text from infographics and charts in articles
- **Bypass paywalls:** Integration with archive services for paywalled security research
- **Content quality scoring:** Auto-assess extraction quality and flag low-quality extractions

### 17.5 Report Generation

- **DOCX export:** Microsoft Word format for enterprise reporting workflows
- **Custom templates:** User-uploadable report templates with variable substitution
- **Scheduled reports:** Auto-generate weekly/monthly intelligence digest PDFs
- **Report sharing:** Generate shareable report links with TLP-based access control
- **Executive dashboard PDF:** One-pager with charts, top threats, trend data
- **MISP event export:** Generate MISP-compatible JSON events from reports

### 17.6 UI Enhancements

- **Highlight customization:** Let users configure which keyword types are highlighted and their colors
- **IOC graph visualization:** Network graph showing relationships between IOCs, threat actors, and CVEs
- **Reading progress tracker:** Track which articles an analyst has read
- **Annotation / notes:** Let analysts add private notes to individual news items
- **Alert rules:** Users define keyword/category alert rules, get notifications for matching articles
- **Comparison view:** Side-by-side comparison of two correlated articles
- **Sentiment/urgency trend:** Timeline chart showing threat urgency over time

### 17.7 Search & Filtering

- **Full-text search (OpenSearch):** Index news_items into OpenSearch for fuzzy, faceted, and semantic search
- **Saved searches:** Let users save filter combinations as named views
- **Smart filters:** "Show me all articles about Exchange Server CVEs in the last 7 days"
- **Related articles:** Powered by embedding similarity, show "Related Intelligence" on detail page
- **Global keyword alerts:** Subscribe to keywords (e.g., "Exchange", "Lazarus") and get notified

### 17.8 Operational

- **Feed health monitoring:** Track per-feed success rates, article counts, last fetch time; alert on degraded feeds
- **Enrichment quality metrics:** Track AI enrichment quality scores, hallucination rates
- **Cost tracking:** Monitor token usage per provider per day
- **Data retention policy:** Auto-archive or purge articles older than N days
- **Export to SIEM:** Send structured alerts to Splunk/Sentinel/QRadar via syslog or REST
- **Webhook integrations:** POST new high-priority articles to Slack, Teams, or PagerDuty
- **Multi-tenant support:** Separate news feeds and enrichment per organization

### 17.9 Performance

- **Connection pooling:** Reuse HTTP connections across RSS fetch cycles
- **Batch DB inserts:** Insert multiple articles in a single DB transaction
- **Incremental dedup:** Use bloom filter for fast source_hash pre-check
- **Parallel enrichment:** Spread enrichment across multiple AI providers simultaneously (not sequentially)
- **CDN for reports:** Cache generated reports in CDN for repeated downloads

---

*Last updated: 2026-03-03. This document is auto-maintained alongside code changes.*
