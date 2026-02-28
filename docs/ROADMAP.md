# IntelWatch — Product Roadmap

> Feature improvement plan organized in phases. Each phase includes new features, modules, pages, and integrations to be added to the IntelWatch Threat Intelligence Platform.
>
> Reference benchmark: [OpenCTI](https://github.com/OpenCTI-Platform/opencti) (8.9k stars, 100+ connectors, STIX2 knowledge graph)

---

## Current State (v1.0)

### Pages
| Page | Description |
|------|-------------|
| Login | SSO login via Cloudflare Zero Trust / Google OAuth |
| Dashboard | Stat cards, severity distribution, trend charts, top risks, feed status |
| Threats | Active threats sorted by risk score, severity filters |
| Intel Feed | Paginated intel items with filtering, CSV/Excel export |
| Intel Detail | Full item view with overview, timeline, AI summary, CVE badges |
| Search | IOC-type auto-detection (CVE, IP, domain, URL, hash, email) |
| IOC Database | Browse all IOCs with type filters, copy-to-clipboard |
| Analytics | Severity bars, feed type charts, geo distribution, trend analysis |
| Geo | Geographic threat distribution with region drill-down |
| Feeds | Feed connector status monitor |
| Settings | General, Security, Notifications, Appearance, Data, API Keys |

### Integrations (7 Feeds)
CISA KEV, NVD, URLhaus, AbuseIPDB, AlienVault OTX, VirusTotal, Shodan

### Core Capabilities
- Dynamic risk scoring (5-factor: KEV, severity, reliability, freshness, prevalence)
- AI summaries via LLM (llama3 / Open-WebUI)
- OpenSearch full-text search with IOC auto-detection
- Excel export with styled formatting
- RBAC (admin/analyst/viewer)
- Audit logging
- Redis caching + job queue
- TimescaleDB hypertables

---

## Phase 1 — High Impact, Moderate Effort

**Goal:** Add the most universally expected TI platform features that differentiate IntelWatch from a simple feed aggregator.

### 1.1 MITRE ATT&CK Integration ✅ DONE (v1.1)
- **Module:** `api/app/services/mitre.py` — fetch ATT&CK Enterprise JSON from MITRE's STIX repo
- **Database:** `attack_techniques` table (691 techniques synced from STIX bundle)
- **Database:** `intel_attack_links` junction table linking intel items to ATT&CK techniques
- **Page:** `/techniques` — Interactive ATT&CK matrix heatmap + searchable list view
- **Page update:** Intel Detail page — ATT&CK tab showing mapped techniques with confidence/tactic
- **Scheduler:** 24h ATT&CK sync + 10min auto-mapping jobs (keyword-based text analysis)
- **API:** 4 new endpoints — list, matrix, detail, intel-techniques
- **UI Component:** `ATTACKMatrix.tsx` — grid visualization of 14 tactics, color-coded by risk
- **Sidebar:** "ATT&CK Map" link added under Investigation section

### 1.2 Relationship Graph Visualization
- **Module:** `api/app/services/graph.py` — build relationship graphs between intel items, IOCs, CVEs, and threat actors
- **Database:** New `relationships` table (source_id, source_type, target_id, target_type, relationship_type, confidence, first_seen, last_seen)
- **Page:** `/investigate` — Interactive graph explorer using D3.js force-directed layout or vis.js
- **Features:**
  - Click any node to expand related entities
  - Filter by relationship type, time range, confidence
  - Highlight shortest path between two entities
  - Export graph as image/JSON
- **UI Component:** `GraphExplorer.tsx`, `GraphNode.tsx`, `GraphControls.tsx`

### 1.3 Notifications & Alerting
- **Module:** `api/app/services/notifications.py` — notification engine with rule evaluation
- **Database:** New `notification_rules` table (id, user_id, name, conditions JSON, channels, is_active)
- **Database:** New `notifications` table (id, user_id, rule_id, title, message, severity, read, created_at)
- **Page update:** Settings → Notifications tab — create/manage alert rules
- **UI Component:** `NotificationBell.tsx` — real-time notification indicator in header (replace static bell)
- **Notification triggers:**
  - New critical/high severity intel item ingested
  - New CISA KEV entry detected
  - Specific CVE ID match (watchlist)
  - Risk score exceeds threshold
  - Feed connector error/stale
- **Channels (start with):**
  - In-app notifications (database-backed)
  - Browser push notifications (Web Push API)

### 1.4 Report Generation
- **Module:** `api/app/services/reports.py` — report builder with templating
- **Database:** New `reports` table (id, title, author_id, type, status, content JSON, created_at, published_at, tlp)
- **Page:** `/reports` — list, create, edit, publish reports
- **Page:** `/reports/new` — report editor with rich text (Tiptap/ProseMirror)
- **Features:**
  - Link intel items, IOCs, ATT&CK techniques to report
  - Auto-generate executive summary via AI
  - Export to PDF (using puppeteer or weasyprint)
  - Export to DOCX
  - TLP marking on reports
  - Status workflow: Draft → Review → Published
- **Sidebar:** Add "Reports" under Investigation section

### 1.5 Complete VirusTotal & Shodan Connectors ✅ DONE
- **Module:** `api/app/services/feeds/virustotal.py` — VT APIv3 connector ✅
  - Fetches malicious files, URLs, domains, IPs from VirusTotal intelligence/public APIs
  - Detection ratio scoring, threat classification, multi-fallback fetch strategy
  - Auto-scheduled every 15 minutes
- **Module:** `api/app/services/feeds/shodan.py` — Shodan API connector ✅
  - Fetches exploit data and exposed host/service information
  - CVE extraction from vulnerabilities, geo-enrichment, service fingerprinting
  - Auto-scheduled every 30 minutes
- **Registration:** Both connectors registered in worker tasks, scheduler, admin routes, and DB seed ✅
- **Page update:** IOC Database — show enrichment data (VT detections, Shodan ports) inline *(future enhancement)*
- **Page update:** Intel Detail — enrichment sidebar showing VT/Shodan data for linked IOCs *(future enhancement)*
- **Feed Status:** VT and Shodan appear in feed status panel automatically ✅

---

## Phase 2 — Differentiation & Analyst Workflow

**Goal:** Transform IntelWatch from a monitoring tool into an analyst workstation with investigation and collaboration features.

### 2.1 Case / Incident Management
- **Module:** `api/app/services/cases.py` — case lifecycle management
- **Database:** New `cases` table (id, title, type, severity, status, assignee_id, priority, description, created_at, closed_at, tlp)
- **Database:** New `case_items` junction table (case_id, item_type, item_id, added_by, added_at, notes)
- **Page:** `/cases` — case list with filters (status, severity, assignee)
- **Page:** `/cases/[id]` — case detail with timeline, linked items, activity log
- **Page:** `/cases/new` — create new case
- **Features:**
  - Case types: Incident Response, Investigation, Request for Information
  - Status workflow: New → In Progress → Pending → Resolved → Closed
  - Assign to team members
  - Link intel items, IOCs, reports to a case
  - Case timeline with activity feed
  - Priority and SLA tracking
- **Sidebar:** Add "Cases" under Investigation section

### 2.2 Analyst Notes & Opinions
- **Module:** `api/app/services/notes.py` — note CRUD with entity linking
- **Database:** New `notes` table (id, author_id, content, entity_type, entity_id, created_at, updated_at)
- **Page update:** Intel Detail — "Notes" tab for analyst commentary
- **Page update:** IOC Database — expandable notes per IOC
- **Page update:** Cases — notes thread on case detail
- **Features:**
  - Markdown support in notes
  - @mention other users
  - Pin important notes
  - Search across all notes

### 2.3 Custom Dashboards
- **Module:** `api/app/services/dashboards.py` — dashboard CRUD and widget configuration
- **Database:** New `custom_dashboards` table (id, name, owner_id, layout JSON, is_default, is_shared, created_at)
- **Database:** New `dashboard_widgets` table (id, dashboard_id, widget_type, title, config JSON, position JSON)
- **Page:** `/dashboards` — dashboard list (my dashboards, shared with me)
- **Page:** `/dashboards/[id]` — rendered dashboard with drag-and-drop grid
- **Page:** `/dashboards/[id]/edit` — dashboard editor
- **Features:**
  - Widget types: stat counter, donut chart, bar chart, line chart, table, heatmap, map, list
  - Configurable data source per widget (feed type, severity, time range, entity type)
  - Drag-and-drop grid layout (react-grid-layout)
  - Share dashboards with team or make public
  - Set as default dashboard (replaces welcome page)
  - Auto-refresh interval per dashboard
- **Sidebar:** Add "Dashboards" under Overview section

### 2.4 Additional Export Formats
- **Module update:** `api/app/services/export.py`
  - Add CSV export (streaming for large datasets)
  - Add PDF export (styled report format with charts)
  - Add STIX2 bundle export (JSON)
  - Add IOC-only export (plain text list for blocklists)
- **Page update:** Intel Feed — export dropdown with format selection
- **Page update:** Search results — export button
- **Formats:**
  - Excel (.xlsx) — existing
  - CSV (.csv) — new
  - PDF (.pdf) — new
  - STIX2 Bundle (.json) — new
  - IOC List (.txt) — new (one IOC per line, for firewall/SIEM import)

### 2.5 IOC Enrichment Service
- **Module:** `api/app/services/enrichment.py` — on-demand and auto enrichment pipeline
- **Features:**
  - Auto-enrich new IOCs during ingestion (configurable per source)
  - On-demand enrichment button on IOC detail
  - Enrichment sources: VirusTotal, Shodan, AbuseIPDB, WHOIS, DNS, GeoIP
  - Store enrichment results in IOC `context` JSONB field
  - Enrichment history with timestamps
  - Rate limiting and API key rotation
- **Page update:** IOC Database — "Enrich" button per IOC, enrichment status indicator
- **UI Component:** `EnrichmentPanel.tsx` — side panel showing enrichment results

---

## Phase 3 — Enterprise Grade & Interoperability

**Goal:** Make IntelWatch interoperable with the broader security ecosystem and suitable for team/enterprise deployment.

### 3.1 STIX2 Import/Export
- **Module:** `api/app/services/stix.py` — STIX2 bundle parser and generator
- **Features:**
  - Parse STIX2 bundles (SDOs: Indicator, Malware, Threat Actor, Campaign, Vulnerability, etc.)
  - Map STIX objects to IntelWatch data model
  - Generate STIX2 bundles from intel items and IOCs
  - Support STIX2.1 patterns for indicators
  - Validate bundles against STIX schema
- **Page:** `/import` — file upload for STIX2, CSV, JSON import
- **API endpoint:** `POST /api/v1/import/stix` — programmatic STIX bundle import

### 3.2 TAXII Feed Support
- **Module:** `api/app/services/feeds/taxii.py` — TAXII 2.1 client connector
- **Features:**
  - Connect to external TAXII servers as a feed source
  - Poll collections for new STIX objects
  - Configure multiple TAXII sources
  - Serve IntelWatch data as a TAXII server (optional)
- **Page update:** Feeds — add/configure TAXII feed sources
- **Database:** New `taxii_sources` table (id, name, url, collection_id, api_key, poll_interval, last_poll)

### 3.3 Retention Policies
- **Module:** `api/app/services/retention.py` — data lifecycle management
- **Database:** New `retention_policies` table (id, name, entity_type, max_age_days, severity_filter, action, is_active)
- **Features:**
  - Auto-delete or archive intel items older than N days
  - Separate policies per severity (keep critical longer)
  - Separate policies per feed type
  - Dry-run mode to preview what would be deleted
  - Audit log of all retention actions
- **Page update:** Settings → Data & Storage — retention policy manager
- **Worker job:** Nightly retention sweep

### 3.4 Playbook Automation
- **Module:** `api/app/services/playbooks.py` — event-driven automation engine
- **Database:** New `playbooks` table (id, name, trigger_type, conditions JSON, actions JSON, is_active, created_by)
- **Database:** New `playbook_runs` table (id, playbook_id, triggered_at, status, input JSON, output JSON)
- **Page:** `/automation` — playbook list and visual builder
- **Features:**
  - Triggers: new intel item, new IOC, risk score threshold, schedule
  - Conditions: severity, feed type, IOC type, geo, tags
  - Actions:
    - Send notification (in-app, email, Slack, webhook)
    - Create case automatically
    - Enrich IOC
    - Tag/label entity
    - Block IOC (export to blocklist)
    - Generate report
  - Visual flow builder (react-flow)
  - Run history and logs
- **Sidebar:** Add "Automation" under System section

### 3.5 MISP Integration
- **Module:** `api/app/services/feeds/misp.py` — MISP connector
- **Features:**
  - Pull events from MISP instances
  - Push intel items to MISP as events
  - Map MISP attributes to IntelWatch IOCs
  - Sync threat levels, tags, and TLP
  - Configure multiple MISP instances
- **Page update:** Feeds — MISP feed source configuration
- **Database:** New `misp_instances` table (id, name, url, api_key, org_id, pull_enabled, push_enabled)

---

## Phase 4 — Advanced Analytics & Scale

**Goal:** Add advanced analytical capabilities and prepare the platform for larger deployments.

### 4.1 Threat Actor Profiles
- **Database:** New `threat_actors` table (id, name, aliases, description, motivation, sophistication, country, first_seen, last_seen, tlp)
- **Database:** New `intel_actor_links` junction table
- **Page:** `/actors` — threat actor gallery with profile cards
- **Page:** `/actors/[id]` — actor profile with linked campaigns, malware, techniques, IOCs, timeline
- **Feed enhancement:** Auto-extract and link threat actor names from intel items
- **Sidebar:** Add "Threat Actors" under Investigation section

### 4.2 Vulnerability Management View
- **Page:** `/vulnerabilities` — dedicated CVE browser
- **Features:**
  - CVE detail cards with CVSS score, EPSS score, KEV status
  - Affected products filter
  - Patch availability status
  - Link to related intel items and IOCs
  - Trending vulnerabilities chart
  - Priority scoring (CVSS + EPSS + KEV + exploit availability)
- **Module:** `api/app/services/feeds/epss.py` — FIRST EPSS score feed connector

### 4.3 Email/Slack Notification Channels
- **Module:** `api/app/services/notifiers/email.py` — SMTP email sender with templates
- **Module:** `api/app/services/notifiers/slack.py` — Slack webhook/bot integration
- **Module:** `api/app/services/notifiers/webhook.py` — generic webhook POST
- **Page update:** Settings → Notifications — configure channels (SMTP server, Slack webhook URL)
- **Templates:** Configurable HTML email templates for different alert types

### 4.4 API Key Management
- **Database:** New `api_keys` table (id, user_id, name, key_hash, prefix, permissions, expires_at, last_used, is_active)
- **Page update:** Settings → API Keys — generate, revoke, view usage
- **Features:**
  - Named API keys with expiration
  - Per-key permission scoping (read-only, full access)
  - Usage tracking and rate limiting
  - Key prefix display (first 8 chars) for identification
- **Middleware:** API key auth alongside session cookies

### 4.5 Dark Mode / Theme System
- **Module update:** Theme provider with system/light/dark mode toggle
- **Page update:** Settings → Appearance — theme selection
- **Implementation:** CSS variables with Tailwind dark: variant (already partially supported)
- **Features:**
  - System preference detection
  - Per-user preference stored in database
  - Smooth transition animation

---

## Phase 5 — Intelligence Sharing & Collaboration

**Goal:** Enable multi-user collaboration, intelligence sharing, and community features.

### 5.1 Watchlists
- **Database:** New `watchlists` table (id, user_id, name, type, items JSON, notifications_enabled)
- **Page:** `/watchlists` — manage personal watchlists
- **Features:**
  - Watch specific CVEs, IPs, domains, threat actors
  - Get notified when watched items appear in new intel
  - Shared team watchlists
  - Quick-add from any entity view

### 5.2 Tags & Taxonomy Management
- **Database:** New `taxonomies` table (id, namespace, key, value, color, description)
- **Page update:** Settings → Taxonomies — manage custom label sets
- **Features:**
  - Custom tag namespaces (e.g., campaign, sector, priority)
  - Color-coded tags
  - Auto-tagging rules based on content patterns
  - Tag-based filtering across all views

### 5.3 Soft Delete & Trash
- **Module update:** Add `deleted_at` column to intel_items, iocs, reports, cases
- **Page:** `/trash` — view and restore deleted items (admin only)
- **Features:**
  - 30-day retention in trash before permanent deletion
  - Restore with all relationships intact
  - Bulk delete and restore

### 5.4 Activity Feed
- **Page:** `/activity` — platform-wide activity timeline
- **Features:**
  - Real-time feed of all platform actions (new intel, new cases, user actions)
  - Filter by action type, user, entity type
  - WebSocket-powered live updates
  - Useful for SOC team awareness

### 5.5 Multi-Language Support
- **Module:** i18n framework integration (next-intl or react-i18next)
- **Languages:** English (default), Spanish, French, German, Japanese
- **Features:**
  - Language selector in settings
  - All UI strings externalized to translation files
  - RTL support preparation

---

## New Pages Summary (All Phases)

| Phase | Page | Route | Description |
|-------|------|-------|-------------|
| 1 | Techniques | `/techniques` | MITRE ATT&CK matrix heatmap |
| 1 | Investigate | `/investigate` | Relationship graph explorer |
| 1 | Reports | `/reports` | Report list and management |
| 1 | Report Editor | `/reports/new` | Create/edit reports |
| 2 | Cases | `/cases` | Case/incident management |
| 2 | Case Detail | `/cases/[id]` | Case timeline and linked items |
| 2 | Dashboards | `/dashboards` | Custom dashboard list |
| 2 | Dashboard View | `/dashboards/[id]` | Rendered custom dashboard |
| 3 | Import | `/import` | File upload (STIX2, CSV, JSON) |
| 3 | Automation | `/automation` | Playbook builder and management |
| 4 | Threat Actors | `/actors` | Threat actor profiles |
| 4 | Actor Detail | `/actors/[id]` | Actor profile with linked intel |
| 4 | Vulnerabilities | `/vulnerabilities` | CVE browser with EPSS/KEV |
| 5 | Watchlists | `/watchlists` | Personal/team watchlists |
| 5 | Activity | `/activity` | Platform activity timeline |
| 5 | Trash | `/trash` | Deleted items recovery |

---

## New Sidebar Navigation (Final State)

```
Overview
  ├── Dashboard
  ├── Dashboards (custom)
  └── Activity

Investigation
  ├── Intel Feed
  ├── Threats
  ├── Threat Actors
  ├── Vulnerabilities
  ├── IOC Database
  ├── Investigate (graph)
  ├── Cases
  ├── Reports
  └── Watchlists

Analytics
  ├── Analytics
  ├── Geo
  └── Techniques (ATT&CK)

System
  ├── Search
  ├── Feeds
  ├── Automation
  ├── Import
  ├── Trash
  └── Settings
```

---

## New Database Tables Summary

| Phase | Table | Purpose |
|-------|-------|---------|
| 1 | `attack_techniques` | MITRE ATT&CK technique catalog |
| 1 | `intel_attack_links` | Intel item ↔ ATT&CK technique mapping |
| 1 | `relationships` | Entity-to-entity relationships |
| 1 | `notification_rules` | User-defined alert rules |
| 1 | `notifications` | Notification delivery log |
| 1 | `reports` | Analyst reports |
| 2 | `cases` | Incident/investigation cases |
| 2 | `case_items` | Case ↔ entity links |
| 2 | `notes` | Analyst notes on entities |
| 2 | `custom_dashboards` | User-created dashboards |
| 2 | `dashboard_widgets` | Dashboard widget configurations |
| 3 | `taxii_sources` | External TAXII feed sources |
| 3 | `retention_policies` | Data lifecycle policies |
| 3 | `playbooks` | Automation playbook definitions |
| 3 | `playbook_runs` | Playbook execution history |
| 3 | `misp_instances` | MISP server configurations |
| 4 | `threat_actors` | Threat actor profiles |
| 4 | `intel_actor_links` | Intel ↔ actor mapping |
| 4 | `api_keys` | API key management |
| 5 | `watchlists` | User watchlists |
| 5 | `taxonomies` | Custom tag taxonomies |

---

## New Integrations Summary

| Phase | Integration | Type | API Key Required |
|-------|-------------|------|-----------------|
| 1 | MITRE ATT&CK | Data source | No |
| 1 | VirusTotal | Enrichment | Yes |
| 1 | Shodan | Enrichment | Yes |
| 2 | WHOIS/DNS | Enrichment | No |
| 2 | GeoIP (MaxMind) | Enrichment | Free tier |
| 3 | TAXII 2.1 | Import/Export | Varies |
| 3 | MISP | Bi-directional | Yes |
| 4 | FIRST EPSS | Data source | No |
| 4 | Slack | Notification | Yes (webhook) |
| 4 | SMTP Email | Notification | Config only |
| 4 | Generic Webhook | Notification | No |

---

*Last updated: February 2026*
*IntelWatch v1.0 — https://intelwatch.trendsmap.in*
