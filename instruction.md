# IntelWatch — Development Instructions

## 3D Design System

The entire UI uses a consistent 3D depth effect to give cards, buttons, and icons a raised, tactile feel.

### CSS Utility Classes (defined in `globals.css`)

| Class | Usage | Effect |
|-------|-------|--------|
| `card-3d` | All `<Card>`, stat cards, panels | Multi-layer box-shadow with inset top highlight; lifts on hover |
| `icon-btn-3d` | Clickable action icon buttons | Raised pill with shadow; lifts on hover, depresses on click |
| `conn-badge-3d` | Connections count badge (non-clickable) | Inset shadow giving a sunken/recessed look |

### Card Component

The base `<Card>` component (`ui/card.tsx`) uses `card-3d` instead of plain `shadow-sm`. Every card in the project automatically gets 3D depth — no per-page overrides needed.

### StatCard

Dashboard stat cards use `card-3d` plus their existing gradient overlays. Icon containers use `text-muted-foreground/60` for visibility.

---

## Action Icons

Every intel item, IOC, or entity card/row should include the standard action icons described below.
Follow this guide when adding new pages or features that display intel or IOC data.

### Standard Icon Set

| Icon | Lucide Name | Default Color | Hover Color | Purpose | Clickable |
|------|-------------|---------------|-------------|---------|-----------|
| **Hunt** | `Crosshair` | `text-blue-400` | `text-blue-300` | Search local + internet | Yes |
| **Investigate** | `Telescope` | `text-purple-400` | `text-purple-300` | Relationship graph | Yes |
| **Connections** | `Share2` | `text-teal-400/70` | — | Show relation count | No |
| **Enrich** | `Zap` | `text-yellow-400` | `text-yellow-300` | Enrich via VT/Shodan | Yes |
| **Copy** | `Copy`/`Check` | `text-muted-foreground` | `text-foreground` | Copy to clipboard | Yes |

### Design Rules

1. **Always-on accent color** — Icons show their accent color at rest (not grey). They brighten on hover.
2. **3D pill buttons** — All clickable icons use the `icon-btn-3d` CSS class. This gives raised depth with shadow.
3. **Hover lift** — Buttons lift 1px on hover (`translateY(-1px)`) with stronger shadow.
4. **Press effect** — On `:active`, buttons sink back down with inset shadow.
5. **Connections badge** — Uses `conn-badge-3d` class (inset/sunken effect). Not clickable.
6. **Size** — Icons are `h-3.5 w-3.5` in tables, `h-3 w-3` in card meta rows.
7. **Labels** — On IntelCard, Hunt and Investigate show a `text-[10px] font-medium` label. Tables use icon-only.
8. **Group hover** — Use named groups (`group/hunt`, `group/inv`, etc.) so the icon brightens when hovering the button container.

### Where Icons Appear

| Page | Component | Layout | Icons Shown |
|------|-----------|--------|-------------|
| **Threat Feed** (`/threats`) | Inline cards | Vertical stack (right side) | Hunt, Investigate, Connections, ChevronRight |
| **Intel Items** (`/intel`) | `IntelCard.tsx` | Horizontal row (meta bar, right-aligned) | Hunt (labeled), Investigate (labeled), Connections (count) |
| **IOC Database** (`/iocs`) | Table `<td>` | Horizontal row | Enrich, Copy, Hunt, Investigate, Connections (count) |

### URL Patterns

- **Hunt**: `/search?q={encodeURIComponent(value)}&hunt=1`
  - For intel items: use `item.source_ref || item.cve_ids[0] || item.title`
  - For IOCs: use `ioc.value`
- **Investigate**: `/investigate?id={encodeURIComponent(id)}&type={intel|ioc}&depth=1`
  - For intel items: `id = item.id`, `type = intel`
  - For IOCs: `id = ioc.value`, `type = ioc`

### Sidebar Icon

The **Investigate** page uses the `Telescope` icon in the sidebar for consistency with the Investigate action icon on cards.

### Adding a New Action Icon

1. Choose a lucide-react icon that clearly represents the action.
2. Pick a unique accent color (e.g., `text-emerald-400` / `text-emerald-300` for hover).
3. Use the `icon-btn-3d` class on the button/link. For display-only, use `conn-badge-3d`.
4. Add a `title` attribute with a short description (e.g., `"Hunt — search local + internet"`).
5. Use `e.stopPropagation()` if inside a clickable card.
6. Add the icon to all 3 pages listed above for consistency.
7. Update this file with the new icon entry.

---

## General Rules

- **Do not remove existing UI features** — only add. If something moves, ensure it still exists somewhere accessible.
- **For any major change**, update the relevant docs (`instruction.md`, `README.md`, or `docs/`).
- **Responsive UI** — All pages must fit all screen sizes including mobile. See `docs/Instruction.md` § Responsive Design for breakpoints. Edge-to-edge layouts, no horizontal overflow.
- **Develop locally** at `E:\code\ti-platform`, push to GitHub, deploy to VPS and test online.
- **Deploy flow**: `git push origin main` → SSH to VPS → `git pull` → `docker compose build ui` → `docker compose up -d ui`.

---

## Keyword Highlighting

All data-rich pages (intel detail, news detail, IOC tables, threat feed) must **visually highlight key entities** inline so analysts can scan quickly.

### Keyword Types to Highlight

| Keyword Type | Examples | Suggested Style |
|---|---|---|
| **Threat Actor (TA)** | APT29, Lazarus Group, FIN7 | `bg-red-500/15 text-red-400` rounded pill |
| **CVE** | CVE-2024-3094 | `bg-orange-500/15 text-orange-400` rounded pill |
| **Date / Timestamp** | 2026-03-01, January 2026 | `text-blue-300 font-medium` |
| **Product / Technology** | Exchange Server, Chrome, Linux | `bg-cyan-500/10 text-cyan-400` rounded pill |
| **Attack / Technique** | phishing, supply chain, RCE | `bg-purple-500/10 text-purple-400` rounded pill |
| **Breach / Incident** | data breach, ransomware attack | `bg-rose-500/10 text-rose-300` |
| **Organization** | Microsoft, CISA, FBI | `bg-emerald-500/10 text-emerald-400` rounded pill |
| **Version / Number** | v3.1.2, 45,000 records, 10 million | `text-yellow-300 font-mono` |
| **IOC** | IP address, hash, domain, URL | `bg-amber-500/10 text-amber-300 font-mono` rounded pill |
| **Malware Family** | LockBit, Emotet, Cobalt Strike | `bg-red-500/10 text-red-300` rounded pill |

### Highlighting Rules

1. **Use subtle background tints** — never solid backgrounds that break dark-theme readability.
2. **Rounded pill badges** (`rounded px-1.5 py-0.5 text-xs`) for entity types; inline `font-medium` for dates/numbers.
3. **Clickable when actionable** — CVEs link to detail, TAs link to search, IOCs link to hunt.
4. **Don't over-highlight** — if >40% of text is highlighted, reduce to the most important entities.
5. **Consistent across pages** — same keyword type always uses the same color everywhere.

---

## Content Readability Standards

All UI pages and components must maximize readability for quick analyst consumption.

### Formatting Rules

- **Bullet points over paragraphs** — Break dense text into bullet lists wherever possible. Never show a wall of text.
- **Tables over lists for structured data** — Any data with 2+ attributes should use a table, not inline text.
- **Bold key terms** — Lead each bullet with the key term in bold (e.g., **Impact:** data exfiltration).
- **Short sentences** — Max ~15 words per bullet. Split if longer.
- **Hierarchy** — Use headings, sub-sections, and dividers. Never dump all info at one level.

### Where to Apply

| Context | Format |
|---|---|
| AI enrichment output (summary, why_it_matters) | Bullet points, highlighted entities |
| Intel detail page sections | Bullets + tables for IOCs, timeline, techniques |
| News detail page | Sectioned cards with bullets per area |
| Tooltip content | 2-3 line max, key info only |
| Feed cards / list items | Badges + short labels, not sentences |
| Dashboard stat cards | Single metric + trend indicator, no paragraphs |

---

## Cyber News Feature

### Overview

A structured, decision-ready intelligence cyber news feed aggregated from 8+ RSS sources with AI enrichment.

### Architecture

| Component | File(s) | Description |
|-----------|---------|-------------|
| DB Schema | `db/schema.sql` | `news_items` table with `news_category` + `confidence_level` enums |
| Model | `api/app/models/models.py` → `NewsItem` | SQLAlchemy 2.0 mapped model |
| Schemas | `api/app/schemas/__init__.py` | `NewsItemResponse`, `NewsListResponse`, `NewsCategoriesResponse` |
| Service | `api/app/services/news.py` | RSS fetcher, AI enrichment prompt, category detection |
| Routes | `api/app/routes/news.py` | `GET /news`, `GET /news/categories`, `GET /news/{id}`, `POST /news/refresh` |
| Worker | `worker/tasks.py` | `ingest_news()`, `enrich_news_batch()` |
| Scheduler | `worker/scheduler.py` | Ingestion every 30 min, AI enrichment every 5 min |
| UI Page | `ui/src/app/(app)/news/page.tsx` | Category widgets (left), news feed (right), skeleton loaders |
| UI Detail | `ui/src/app/(app)/news/[id]/page.tsx` | Headline strip, why-it-matters cards, IOC summary, timeline, detection/mitigation |
| TypeScript | `ui/src/types/index.ts` | `NewsItem`, `NewsCategory`, `NewsListResponse`, etc. |
| API Client | `ui/src/lib/api.ts` | `getNews()`, `getNewsItem()`, `getNewsCategories()`, `refreshNews()` |
| Sidebar | `ui/src/components/Sidebar.tsx` | `Newspaper` icon in Overview section |

### Nine Categories

`active_threats`, `exploited_vulnerabilities`, `ransomware_breaches`, `nation_state`, `cloud_identity`, `ot_ics`, `security_research`, `tools_technology`, `policy_regulation`

### RSS Sources

BleepingComputer, The Hacker News, Krebs on Security, Dark Reading, SecurityWeek, CISA Alerts, Threatpost, The Record

### AI Enrichment Schema

Each article is enriched into structured JSON with: summary, why_it_matters, threat_actors, malware_families, CVEs, MITRE ATT&CK techniques, IOC summary, timeline, detection/mitigation, relevance_score (1-100), confidence (high/medium/low).

### Re-Enrichment Pipeline

When AI provider tokens are exhausted (daily quota limits), articles receive **fallback enrichment** — headline-only summary, `confidence=low`, `relevance_score=30`, no executive_brief.

The `re_enrich_fallback_news()` task automatically upgrades these once tokens reset:

| Setting | Value |
|---------|-------|
| Schedule | Every 15 minutes |
| Batch size | 10 articles per run |
| Retry window | 48 hours from article creation |
| Detection criteria | `ai_enriched=True`, `confidence=low`, `score<=30`, no `executive_brief` |
| Smart backoff | Aborts after 2 consecutive failures (all providers rate-limited) |
| Priority | Newest articles first |

**Flow:**
1. Article ingested → `enrich_news_batch()` attempts AI enrichment every 5 min
2. If all AI providers fail for >30 min → fallback enrichment (headline-only) applied
3. `re_enrich_fallback_news()` picks up fallback articles every 15 min
4. If tokens available → upgrades to full enrichment (summary, executive_brief, tags, etc.)
5. If tokens still exhausted → smart backoff, retries next cycle
6. Once daily quotas reset → all remaining fallback articles get fully enriched

Both `enrich_news_batch()` and `re_enrich_fallback_news()` use smart backoff to stop wasting API calls when providers are rate-limited.
