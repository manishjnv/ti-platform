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

## Phase 6 — Competitive Moat & Unique Differentiators

**Goal:** Features that no open-source TI platform offers — brand protection, underground monitoring, AI-assisted hunting, and customer-specific curated intel. These are the features that justify the tagline: *"The only TI platform that protects your brand, monitors the dark web, and hunts threats with AI."*

### 6.1 Brand Takedown Automation
- **Module:** `api/app/services/takedown.py` — automated abuse report submission and evidence packaging
- **Database:** New `takedown_requests` table (id, org_id, target_type, target_url, target_domain, platform, status, evidence JSON, submitted_at, resolved_at, resolution)
- **Database:** New `brand_monitors` table (id, org_id, brand_name, keywords[], domains[], social_handles[], logo_hash, is_active)
- **Page:** `/takedowns` — takedown request dashboard with status tracking (Submitted → Under Review → Actioned → Resolved/Rejected)
- **Page:** `/takedowns/new` — create takedown request with evidence builder
- **Page:** `/brand` — brand monitoring dashboard showing impersonation alerts, lookalike domains, policy violations
- **Features:**
  - **Lookalike domain detection** — monitor Certificate Transparency logs (crt.sh), DNS registrations, and typosquatting patterns (homoglyph, bit-flip, keyword-append) against registered brand domains
  - **Social media impersonation** — scan Meta (Graph API), X/Twitter (abuse API), LinkedIn, Telegram for fake profiles using brand name/logo
  - **Evidence packaging** — auto-capture screenshots (Playwright headless), WHOIS snapshots, DNS history, web archive links, and bundle as PDF evidence packet
  - **Automated submission** — submit abuse reports to:
    - Domain registrars via ICANN UDRP/URS process templates
    - Hosting providers via abuse@ email (auto-detected from WHOIS)
    - Google Safe Browsing (report phishing URL)
    - Meta (Graph API content takedown)
    - X/Twitter (abuse report API)
    - Cloudflare (abuse report for CF-proxied sites)
    - GitHub (DMCA/phishing page report)
  - **Copyright/trademark templates** — pre-built legal templates for DMCA, trademark infringement, impersonation
  - **Status tracking** — webhook/email polling for takedown resolution status
  - **Analytics** — takedown success rate, average resolution time by platform, repeat offenders
- **Sidebar:** Add "Brand Protection" section with "Takedowns" and "Brand Monitor" links
- **Scheduler:** Hourly brand monitoring scan, daily CT log check

### 6.2 Dark Web & Credential Leak Monitoring
- **Module:** `api/app/services/darkweb.py` — dark web scraping orchestrator and leak parser
- **Module:** `api/app/services/feeds/darkweb_scraper.py` — Tor .onion site crawler via SOCKS5 proxy
- **Module:** `api/app/services/feeds/paste_monitor.py` — paste site monitor (Pastebin, Ghostbin, Rentry, GitHub Gists)
- **Module:** `api/app/services/feeds/telegram_monitor.py` — Telegram channel/group monitor via Telethon
- **Database:** New `dark_web_sources` table (id, name, type, url, last_scraped, status, config JSON)
- **Database:** New `credential_leaks` table (id, source_id, email, domain, password_hash, plain_text, leak_date, discovered_at, org_id, severity)
- **Database:** New `dark_web_mentions` table (id, source_id, content_snippet, matched_keywords[], entity_type, entity_value, discovered_at, url, risk_score)
- **Page:** `/darkweb` — dark web monitoring dashboard with tabs: Credential Leaks, Mentions, Sources
- **Page:** `/darkweb/leaks` — searchable credential leak database with domain grouping
- **Features:**
  - **Tor scraping** — crawl known dark web marketplaces, forums, paste sites via Tor SOCKS5 proxy (configurable tor container)
  - **Paste monitoring** — poll paste sites every 5 minutes for keywords, domains, email patterns
  - **Telegram monitoring** — join and monitor threat actor Telegram channels/groups for data dumps, breach announcements
  - **Credential parsing** — extract email:password pairs from leaked dumps, hash detection (MD5/SHA1/bcrypt), normalize and deduplicate
  - **Domain alerting** — alert when company domains appear in credential dumps (match against org's registered domains)
  - **Breach correlation** — correlate leaked credentials against known breach databases (HIBP API integration)
  - **VIP monitoring** — special alerting for executive/C-suite email addresses
  - **Data sanitization** — hash or redact plaintext passwords in storage, configurable retention
- **Sidebar:** Add "Dark Web" under Investigation section
- **Scheduler:** 5min paste scan, 15min Telegram poll, 6h Tor crawl cycle
- **Docker:** Optional `tor-proxy` sidecar container for .onion access

### 6.3 AI Threat Hunting Copilot
- **Module:** `api/app/services/ai_copilot.py` — natural language query engine over threat intelligence data
- **Module:** `api/app/services/ai_hypothesis.py` — AI-powered threat hypothesis generator
- **Database:** New `copilot_sessions` table (id, user_id, title, messages JSON, context JSON, created_at, updated_at)
- **Database:** New `hunt_hypotheses` table (id, session_id, hypothesis, confidence, supporting_evidence JSON, status, created_by)
- **Page:** `/hunt` — AI copilot chat interface with threat data context
- **Features:**
  - **Natural language querying** — ask questions like:
    - *"Show me all ransomware IOCs targeting healthcare in the last 30 days"*
    - *"Which ATT&CK techniques are most common in our recent phishing intel?"*
    - *"Find IOCs related to APT28 that overlap with our network ranges"*
    - *"Summarize today's critical threats and recommend priority actions"*
  - **Query-to-filter translation** — LLM converts natural language to structured API filters (severity, feed_type, tags, date range, ATT&CK tactic)
  - **Hypothesis generation** — AI analyzes patterns in your intel data and suggests hunting hypotheses:
    - Potential attack chains based on observed IOC clusters
    - Predicted next-stage techniques based on ATT&CK sequence analysis
    - Anomaly detection in feed patterns (sudden spike in specific threat types)
  - **Context-aware responses** — copilot has access to your intel items, IOCs, ATT&CK mappings, and organizational context
  - **Session persistence** — save and resume hunting sessions
  - **Export findings** — convert copilot findings into reports or case items with one click
  - **LLM backends** — support local (Ollama/llama3), OpenAI, Anthropic, or Azure OpenAI
- **Sidebar:** Add "Threat Hunt" under Investigation section
- **API:** `POST /api/v1/copilot/query` — send natural language query, get structured response

### 6.4 Attack Surface Discovery
- **Module:** `api/app/services/attack_surface.py` — external attack surface mapper
- **Module:** `api/app/services/feeds/crtsh.py` — Certificate Transparency log monitor
- **Module:** `api/app/services/feeds/censys.py` — Censys search connector (free tier)
- **Database:** New `org_assets` table (id, org_id, asset_type, value, discovered_by, first_seen, last_seen, status, risk_score, metadata JSON)
- **Database:** New `asset_findings` table (id, asset_id, finding_type, severity, title, description, evidence JSON, discovered_at, resolved_at)
- **Page:** `/attack-surface` — external asset inventory with risk scoring
- **Page:** `/attack-surface/[id]` — asset detail with findings, history, linked intel
- **Features:**
  - **Subdomain enumeration** — crt.sh Certificate Transparency, DNS brute-force (common wordlists), recursive discovery
  - **Exposed service detection** — correlate with Shodan/Censys for open ports, outdated services, misconfigurations
  - **Certificate monitoring** — alert on new/expiring/misissued certificates for org domains
  - **Technology fingerprinting** — detect web technologies, CMS versions, frameworks (Wappalyzer-style)
  - **Cloud asset discovery** — detect S3 buckets, Azure blobs, GCP storage with org keywords
  - **Risk scoring** — score each asset based on: exposure level, known vulnerabilities, patch status, configuration issues
  - **Change detection** — alert when new assets appear, services change, or configurations drift
  - **Intel correlation** — auto-match discovered assets against intel items (is this IP/domain in our threat data?)
- **Sidebar:** Add "Attack Surface" under Analytics section
- **Scheduler:** Daily subdomain scan, 6h service check, 12h CT log poll

### 6.5 Detection Rule Generator
- **Module:** `api/app/services/detection.py` — rule generation engine from IOCs and ATT&CK mappings
- **Database:** New `detection_rules` table (id, name, rule_type, content, source_iocs[], technique_ids[], severity, created_by, created_at, exported_at)
- **Page:** `/detections` — detection rule library with export
- **Page:** `/detections/generate` — rule generator wizard
- **Features:**
  - **Auto-generate from IOCs:**
    - **Sigma rules** — generic detection rules (translatable to any SIEM)
    - **YARA rules** — file/memory pattern matching rules from hash/string IOCs
    - **Snort/Suricata rules** — network IDS signatures from IP/domain/URL IOCs
    - **KQL (Microsoft Sentinel)** — Kusto queries for Azure environments
    - **SPL (Splunk)** — Splunk search queries
    - **Elastic EQL** — Elasticsearch event query language
  - **ATT&CK-mapped rules** — generate detection logic per ATT&CK technique using technique's data_sources field
  - **Bulk generation** — select multiple IOCs/techniques → generate rule pack
  - **Rule validation** — syntax check before export
  - **Version tracking** — rule versioning with change history
  - **One-click export** — download as .yml (Sigma), .yar (YARA), .rules (Snort), or copy to clipboard
  - **SIEM push** — direct API push to Splunk, Elastic, Sentinel (future)
- **Sidebar:** Add "Detections" under Investigation section

### 6.6 Compliance Threat Mapping
- **Module:** `api/app/services/compliance.py` — threat-to-compliance framework mapper
- **Database:** New `compliance_frameworks` table (id, name, version, controls JSON) — pre-loaded: NIST CSF 2.0, ISO 27001:2022, PCI DSS 4.0, SOC 2, HIPAA, CIS Controls v8
- **Database:** New `threat_control_mappings` table (id, technique_id, framework_id, control_id, relevance_score)
- **Page:** `/compliance` — compliance posture dashboard
- **Page:** `/compliance/[framework]` — framework-specific control view with threat heatmap
- **Features:**
  - **Auto-mapping** — map active threats and ATT&CK techniques to compliance controls automatically
  - **Control gap analysis** — identify which controls are most impacted by current threat landscape
  - **Risk quantification** — score each control's exposure based on active intel (high-severity threats → higher control risk)
  - **Executive reports** — generate board-ready PDF: "These 5 controls are at elevated risk due to active threat campaigns"
  - **Audit evidence** — export compliance mapping history as audit trail (what threats matched which controls, when)
  - **Framework comparison** — side-by-side view across frameworks (one threat → NIST + ISO + PCI impact)
  - **Pre-loaded frameworks:**
    - NIST CSF 2.0 (6 functions, 22 categories, 106 subcategories)
    - ISO 27001:2022 (93 controls)
    - PCI DSS 4.0 (12 requirements, 64 sub-requirements)
    - SOC 2 (5 trust service criteria)
    - HIPAA Security Rule (42 specifications)
    - CIS Controls v8 (18 controls, 153 safeguards)
- **Sidebar:** Add "Compliance" under Analytics section

### 6.7 Customer Asset Onboarding & Curated Intel
- **Module:** `api/app/services/onboarding.py` — guided onboarding wizard and asset profiling engine
- **Module:** `api/app/services/curated_feed.py` — personalized intel feed generator based on asset profile
- **Database:** New `organizations` table (id, name, industry, size, region, domains[], ip_ranges[], brands[], technologies[], compliance_frameworks[], onboarding_complete, created_at)
- **Database:** New `org_assets_profile` table (id, org_id, asset_category, asset_type, asset_value, exposure_level, criticality, metadata JSON)
- **Database:** New `feed_relevance_rules` table (id, org_id, rule_type, condition JSON, weight, is_active) — per-org rules for scoring intel relevance
- **Database:** New `curated_intel_scores` table (intel_id, intel_ingested_at, org_id, relevance_score, matched_assets[], matched_rules[], scored_at)
- **Page:** `/onboarding` — multi-step onboarding wizard (shown on first login or new org setup)
- **Page:** `/my-intel` — personalized, curated intel feed filtered and ranked by org relevance
- **Page:** Settings → "Asset Profile" — edit organization assets after onboarding
- **Features:**
  - **Guided onboarding wizard** (5 steps):
    1. **Organization profile** — company name, industry (dropdown: Finance, Healthcare, Retail, Tech, Gov, etc.), size, region
    2. **Domain & brand inventory** — register owned domains, brand names, social media handles, logo upload
    3. **Network & infrastructure** — IP ranges/CIDRs, cloud providers (AWS/Azure/GCP), hosting providers, CDN
    4. **Technology stack** — operating systems, web servers, databases, CMS, frameworks, SaaS tools (auto-detect from asset scan if available)
    5. **Compliance requirements** — select applicable frameworks (NIST, ISO, PCI, HIPAA, SOC2)
  - **Relevance scoring engine** — every incoming intel item is scored against the org profile:
    - CVE matches org's technology stack → high relevance
    - Threat targets org's industry (e.g., "healthcare ransomware") → high relevance
    - IOC matches org's IP ranges or domains → critical relevance
    - Geo targeting matches org's region → elevated relevance
    - ATT&CK techniques match org's attack surface → elevated relevance
    - Brand/keyword mentions → critical relevance
  - **Curated feed** — `/my-intel` page shows only relevant intel, sorted by relevance × risk score
  - **Feed digest** — daily/weekly email summary of top relevant threats (integrates with notification channels)
  - **Multi-tenancy ready** — each organization gets its own asset profile and curated view
  - **Asset auto-discovery** — integrates with Attack Surface Discovery (6.4) to auto-populate assets during onboarding
  - **Relevance tuning** — analysts can thumbs-up/thumbs-down curated items to train the relevance model
  - **Industry threat briefing** — pre-built threat intelligence briefs per industry vertical, auto-generated from feed data
- **Sidebar:** Add "My Intel" under Overview section, add "Onboarding" under System section
- **Scheduler:** Score new intel items against all org profiles on ingestion (inline hook + 5min catch-up batch)

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
| 6 | Takedowns | `/takedowns` | Brand takedown request dashboard |
| 6 | New Takedown | `/takedowns/new` | Create takedown with evidence |
| 6 | Brand Monitor | `/brand` | Impersonation & lookalike detection |
| 6 | Dark Web | `/darkweb` | Dark web monitoring dashboard |
| 6 | Credential Leaks | `/darkweb/leaks` | Searchable leak database |
| 6 | Threat Hunt | `/hunt` | AI copilot chat interface |
| 6 | Attack Surface | `/attack-surface` | External asset inventory |
| 6 | Asset Detail | `/attack-surface/[id]` | Asset findings & linked intel |
| 6 | Detections | `/detections` | Detection rule library |
| 6 | Rule Generator | `/detections/generate` | IOC→rule generation wizard |
| 6 | Compliance | `/compliance` | Compliance posture dashboard |
| 6 | Framework View | `/compliance/[framework]` | Control-level threat heatmap |
| 6 | Onboarding | `/onboarding` | Multi-step asset profiling wizard |
| 6 | My Intel | `/my-intel` | Curated intel feed per org |

---

## New Sidebar Navigation (Final State)

```
Overview
  ├── Dashboard
  ├── My Intel (curated)
  ├── Dashboards (custom)
  └── Activity

Investigation
  ├── Intel Feed
  ├── Threats
  ├── Threat Actors
  ├── Vulnerabilities
  ├── IOC Database
  ├── Investigate (graph)
  ├── Threat Hunt (AI)
  ├── Cases
  ├── Reports
  ├── Detections
  └── Watchlists

Brand & Exposure
  ├── Brand Monitor
  ├── Takedowns
  ├── Dark Web
  └── Attack Surface

Analytics
  ├── Analytics
  ├── Geo
  ├── Techniques (ATT&CK)
  └── Compliance

System
  ├── Search
  ├── Feeds
  ├── Automation
  ├── Onboarding
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
| 6 | `takedown_requests` | Brand takedown requests & evidence |
| 6 | `brand_monitors` | Brand monitoring configurations |
| 6 | `dark_web_sources` | Dark web / paste / Telegram sources |
| 6 | `credential_leaks` | Parsed credential leak records |
| 6 | `dark_web_mentions` | Keyword/brand mentions on dark web |
| 6 | `copilot_sessions` | AI threat hunting chat sessions |
| 6 | `hunt_hypotheses` | AI-generated hunting hypotheses |
| 6 | `org_assets` | Discovered external assets |
| 6 | `asset_findings` | Security findings per asset |
| 6 | `detection_rules` | Generated Sigma/YARA/Snort rules |
| 6 | `compliance_frameworks` | Pre-loaded compliance frameworks |
| 6 | `threat_control_mappings` | ATT&CK technique → control maps |
| 6 | `organizations` | Customer org profiles & asset inventory |
| 6 | `org_assets_profile` | Detailed org asset categories |
| 6 | `feed_relevance_rules` | Per-org intel relevance scoring rules |
| 6 | `curated_intel_scores` | Per-org relevance scores for intel |

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
| 6 | crt.sh (CT logs) | Asset discovery | No |
| 6 | Censys | Asset discovery | Free tier |
| 6 | Tor SOCKS5 proxy | Dark web crawler | No (self-hosted) |
| 6 | Pastebin/Ghostbin | Leak monitoring | No |
| 6 | Telegram (Telethon) | Channel monitoring | API ID (free) |
| 6 | HIBP (Have I Been Pwned) | Breach correlation | Yes |
| 6 | Meta Graph API | Social takedown | Yes |
| 6 | X/Twitter Abuse API | Social takedown | Yes |
| 6 | Google Safe Browsing | Phishing reporting | Yes (free) |
| 6 | Ollama / OpenAI / Anthropic | AI Copilot | Varies |
| 6 | Sigma/YARA/Snort | Detection export | No |
| 6 | NIST/ISO/PCI/HIPAA/SOC2/CIS | Compliance frameworks | No |

---

## Phase 7 — Monetization, Premium Feeds & Cloud Scale

**Goal:** Transition from free/open feeds to paid premium intel sources as revenue allows, and migrate infrastructure from single VPS to a scalable, resilient cloud platform. Triggered by: **first paying customer.**

### 7.1 Premium Intel Feed Subscriptions
- **Trigger:** First customer revenue covers feed costs (~$200-500/mo to start)
- **Module update:** `api/app/services/feeds/` — upgrade existing connectors + add paid sources
- **Feeds to upgrade (free → paid tier):**

| Feed | Free Tier (Current) | Paid Tier | Cost | Value Add |
|------|---------------------|-----------|------|-----------|
| VirusTotal | 500 req/day, public API | VT Enterprise / VT Intelligence | ~$600/yr | Full threat hunting, retrohunt, livehunt, YARA scanning |
| Shodan | CVEDB (no auth) | Shodan Enterprise API | ~$360/yr | Real-time CVE alerts, network monitoring, 100M+ records |
| AbuseIPDB | 1k checks/day | Premium (100k checks/day) | ~$200/yr | Bulk checking, subnet reports, confidence scoring |
| MaxMind GeoIP | GeoLite2 (free) | GeoIP2 Precision | ~$240/yr | City-level accuracy, ISP/org data, connection type |

- **New premium feeds to add:**

| Feed | Provider | Cost | Capability |
|------|----------|------|------------|
| Recorded Future | Recorded Future | ~$10k/yr (startup tier) | Premium threat intel, IP risk scores, vulnerability intelligence |
| GreyNoise | GreyNoise | ~$1.2k/yr | Mass scanner identification, noise vs. targeted attacks |
| Pulsedive | Pulsedive | ~$600/yr | Community + premium threat indicators, risk scoring |
| IntelX | Intelligence X | ~$2k/yr | Dark web, paste, leak search engine API |
| SpamHaus | Spamhaus | ~$500/yr | DNS blocklists, botnet C2 feeds, DROP/EDROP |
| PhishTank | PhishTank (Cisco) | Free/Premium | Community-verified phishing URLs |
| Abuse.ch (ThreatFox) | abuse.ch | Free | IOCs from malware analysis (complement URLhaus) |
| Binary Defense | Binary Defense | ~$1.2k/yr | Artillery threat intel, banlist, honeypot data |
| CrowdSec | CrowdSec | Free/Premium | Community-driven IP reputation, crowdsourced blocklists |
| CIRCL MISP feeds | CIRCL | Free | OSINT MISP events, malware hashes, botnet trackers |

- **Feed priority tiers:**
  - **Tier 0 (keep free):** MITRE ATT&CK, NVD, CISA KEV, abuse.ch (URLhaus + ThreatFox), CIRCL, CrowdSec, OTX
  - **Tier 1 (first $500/mo revenue):** Upgrade VT, Shodan, AbuseIPDB to paid; add GreyNoise + Pulsedive
  - **Tier 2 (first $2k/mo revenue):** Add IntelX, SpamHaus, Binary Defense; upgrade GeoIP
  - **Tier 3 ($5k+/mo revenue):** Add Recorded Future or equivalent premium feed; enterprise VT

### 7.2 Customer API Access & Usage-Based Billing
- **Module:** `api/app/services/billing.py` — usage metering and subscription management
- **Module:** `api/app/middleware/rate_limit.py` — per-customer API rate limiting and quota enforcement
- **Database:** New `subscriptions` table (id, org_id, plan, status, started_at, expires_at, stripe_id)
- **Database:** New `api_usage_log` table (id, org_id, api_key_id, endpoint, timestamp, response_time, status_code)
- **Database:** New `plans` table (id, name, price_monthly, price_annual, api_calls_limit, intel_items_limit, users_limit, features JSON)
- **Features:**
  - **Plan tiers:**
    - **Community (free):** 1 user, 1k API calls/day, 7 free feeds, 30-day retention
    - **Starter ($49/mo):** 5 users, 10k API calls/day, Tier 0+1 feeds, 90-day retention, email alerts
    - **Professional ($199/mo):** 25 users, 100k API calls/day, all feeds, 1-year retention, dark web monitor, AI copilot
    - **Enterprise ($499+/mo):** Unlimited users, unlimited API, all feeds, unlimited retention, brand takedown, compliance, dedicated support
  - **Stripe integration** — subscription checkout, invoicing, usage-based overages
  - **Usage dashboard** — real-time API call tracking, quota visualization, cost projection
  - **Metered billing** — charge per excess API call or per premium enrichment lookup
- **Page:** Settings → "Subscription" — plan selection, billing history, usage stats
- **API:** Rate limit headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`) on all responses

### 7.3 Infrastructure Migration — Single VPS → Cloud Platform
- **Goal:** Move from single Hostinger KVM 2 VPS ($15/mo) to scalable cloud infrastructure when first customers demand reliability (99.9% uptime SLA)
- **Migration phases:**

#### Stage 1: Enhanced VPS ($15-50/mo) — 1-10 customers
- Current: Hostinger KVM 2 (4 vCPU, 8GB RAM, 100GB SSD) — $15/mo
- Upgrade: Hostinger KVM 4 or Hetzner CX41 (8 vCPU, 16GB RAM, 200GB SSD) — $30-50/mo
- Add: automated backups (daily DB dump to S3/Backblaze B2), health monitoring (UptimeRobot/Healthchecks.io)
- Add: Docker Compose with resource limits, restart policies, log rotation
- Add: Let's Encrypt SSL + Cloudflare CDN for static assets

#### Stage 2: Container Platform ($100-300/mo) — 10-50 customers
- **Option A: Railway.app / Render** — managed container hosting
  - Deploy each service (API, UI, worker, scheduler) as separate Railway service
  - Managed PostgreSQL + Redis add-ons
  - Auto-scaling, zero-downtime deploys, built-in CI/CD
  - Cost: ~$100-200/mo for moderate workloads
  - Pros: simplest migration from Docker Compose, minimal ops overhead

- **Option B: Hetzner Cloud + k3s**
  - 3-node k3s cluster (each 4 vCPU, 8GB) — ~$45/mo total
  - Hetzner managed load balancer — $5/mo
  - Hetzner managed volumes for DB persistence
  - Self-managed but extremely cost-effective
  - Pros: 10x cheaper than AWS/GCP at same specs, EU data residency option

- **Option C: DigitalOcean App Platform**
  - Container-native PaaS with managed databases
  - PostgreSQL managed cluster ($30/mo starter)
  - Redis managed ($15/mo)
  - App containers with auto-scaling
  - Cost: ~$150-250/mo
  - Pros: good middle ground, managed DBs reduce ops

#### Stage 3: Full Cloud ($300-1k/mo) — 50-200 customers
- **Recommended: AWS (or GCP) with managed services**
  - **Compute:** ECS Fargate (API, worker, scheduler) — serverless containers, pay per vCPU-second
  - **Database:** RDS PostgreSQL (with TimescaleDB extension) — Multi-AZ for HA
  - **Search:** Amazon OpenSearch Service (managed) or self-hosted on EC2
  - **Cache:** ElastiCache Redis
  - **CDN:** CloudFront for UI static assets
  - **Storage:** S3 for report exports, evidence files, backups
  - **Monitoring:** CloudWatch + PagerDuty for alerting
  - **CI/CD:** GitHub Actions → ECR → ECS rolling deploy
  - **Cost estimate:** $300-600/mo (reserved instances)
  - **Note:** If EU data residency needed, use Hetzner/OVH or AWS eu-central-1

#### Stage 4: Multi-Region ($1k+/mo) — 200+ customers
- Multi-region deployment (US-East, EU-West, APAC)
- Read replicas for PostgreSQL
- OpenSearch cross-cluster replication
- Global CDN for UI
- Regional API endpoints with geo-routing
- Disaster recovery: RPO < 1h, RTO < 15min

- **Decision matrix:**

| Criteria | VPS (current) | Railway/Render | Hetzner k3s | AWS/GCP |
|----------|---------------|----------------|-------------|---------|
| Monthly cost | $15 | $100-200 | $50-100 | $300-600 |
| Max customers | ~10 | ~100 | ~200 | Unlimited |
| Ops overhead | Medium | Low | High | Medium |
| Auto-scaling | No | Yes | Manual | Yes |
| Uptime SLA | ~99% | 99.9% | 99.5% | 99.99% |
| DB management | Self | Managed | Self | Managed |
| Migration effort | — | Low | Medium | High |
| Data residency | Fixed | US/EU | EU | Any |

### 7.4 Multi-Tenancy Architecture
- **Module:** `api/app/middleware/tenant.py` — tenant isolation middleware
- **Database:** Add `org_id` column to: `intel_items`, `iocs`, `intel_ioc_links`, `cases`, `reports`, `notification_rules`, `watchlists`, `detection_rules`
- **Features:**
  - **Row-level security** — PostgreSQL RLS policies ensuring tenants only see their own data
  - **Shared feed data** — global intel/IOC data shared read-only; per-org enrichments, notes, cases are isolated
  - **Tenant-aware caching** — Redis key prefixing with `org:{id}:`
  - **Admin super-tenant** — platform admin can view all orgs, manage subscriptions, monitor health
  - **Tenant provisioning** — auto-create org schema/namespace on signup
  - **Data export** — per-tenant data export for compliance/portability (GDPR right to data portability)
- **Migration:** Backfill `org_id` on existing data as "default" org, then enforce on new records

### 7.5 High Availability & Observability
- **Module:** `api/app/core/telemetry.py` — OpenTelemetry instrumentation
- **Features:**
  - **Health checks** — deep health endpoints checking DB, Redis, OpenSearch, worker queue depth
  - **Metrics** — Prometheus-compatible metrics endpoint: request latency, error rates, queue depth, feed freshness, cache hit ratio
  - **Distributed tracing** — OpenTelemetry traces across API → worker → DB
  - **Structured logging** — JSON logs with correlation IDs, shipped to Loki/CloudWatch
  - **Alerting** — PagerDuty/OpsGenie integration for: service down, feed stale > 2h, error rate > 5%, disk > 80%
  - **Status page** — public status page (Instatus/Cachet) showing service health
  - **Disaster recovery:**
    - Automated daily DB backups to S3 (30-day retention)
    - Point-in-time recovery via WAL archiving
    - Documented runbook for failover procedures
    - Tested monthly DR drill

---

*Last updated: February 2026*
*IntelWatch v1.0 — https://intelwatch.trendsmap.in*
