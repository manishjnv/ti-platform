# Architecture

> **Living document** — updated when architecture changes are made.

---

## Table of Contents

- [System Overview](#system-overview)
- [High-Level Architecture](#high-level-architecture)
- [Service Topology](#service-topology)
- [Data Architecture](#data-architecture)
- [API Architecture](#api-architecture)
- [Frontend Architecture](#frontend-architecture)
- [Worker Architecture](#worker-architecture)
- [Security Architecture](#security-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Codebase Metrics](#codebase-metrics)

---

## System Overview

The IntelWatch TI Platform is a **self-hosted, containerized** system that aggregates, normalizes, scores, and visualizes threat intelligence from multiple open-source feeds. It is designed as a modular monolith — each concern is cleanly separated into its own layer and can be independently scaled.

**Core principles:**

- Async-first backend (no blocking I/O)
- Event-driven ingestion (Redis Queue)
- Time-series optimized storage (TimescaleDB)
- Full-text search (OpenSearch)
- Stateless API + stateful workers
- SSO-gated access (Cloudflare Zero Trust)

---

## High-Level Architecture

```text
                    ┌───────────────────────────────────────────────┐
                    │              Cloudflare Edge                  │
                    │  ┌─────────────┐    ┌──────────────────┐     │
Internet ──────────►│  │  Zero Trust │    │  Tunnel (Argo)   │     │
                    │  │  SSO/RBAC   │───►│  ti.domain.com   │     │
                    │  └─────────────┘    └────────┬─────────┘     │
                    └──────────────────────────────┼───────────────┘
                                                   │
                    ┌──────────────────────────────┼───────────────┐
                    │         Docker Host           │               │
                    │                              ▼               │
                    │  ┌──────────┐    ┌──────────────────┐        │
                    │  │          │    │                  │        │
                    │  │   UI     │───►│   API Server     │        │
                    │  │ (Next.js)│    │   (FastAPI)      │        │
                    │  │  :3000   │    │   :8000          │        │
                    │  └──────────┘    └────┬──────┬──────┘        │
                    │                       │      │               │
                    │              ┌────────┘      └────────┐      │
                    │              ▼                        ▼      │
                    │  ┌──────────────────┐    ┌───────────────┐   │
                    │  │  PostgreSQL +    │    │    Redis      │   │
                    │  │  TimescaleDB    │    │   :6379       │   │
                    │  │  :5432          │    └───┬───────┬───┘   │
                    │  └──────────────────┘        │       │       │
                    │                              ▼       ▼       │
                    │  ┌──────────────────┐    ┌───────────────┐   │
                    │  │   OpenSearch     │    │    Worker     │   │
                    │  │   :9200         │    │   + Scheduler │   │
                    │  └──────────────────┘    └───────────────┘   │
                    └──────────────────────────────────────────────┘
```

---

## Service Topology

| Service | Compose Name | Technology | Responsibility | Port |
| ------- | ------------ | ---------- | --------------- | ---- |
| **UI** | `ui` | Next.js 14, TypeScript, Tailwind CSS | Server-side rendered dashboard, client-side interactivity | 3000 |
| **API** | `api` | FastAPI, async SQLAlchemy, Pydantic v2 | REST API, auth middleware, data access layer | 8000 |
| **Worker** | `worker` | Python RQ | Background feed ingestion, AI summarization | — |
| **Scheduler** | `scheduler` | APScheduler | Cron-driven job enqueueing | — |
| **PostgreSQL** | `postgres` | PostgreSQL 16 + TimescaleDB | Primary data store (time-series hypertables) | 5432 |
| **Redis** | `redis` | Redis 7 Alpine | Job queue (RQ) + API response cache | 6379 |
| **OpenSearch** | `opensearch` | OpenSearch 2.13 | Full-text IOC search + analytics | 9200 |

### Service Dependencies

```text
UI ──► API ──► PostgreSQL (health check: service_healthy)
              ──► Redis (health check: service_healthy)
              ──► OpenSearch (health check: service_healthy)

Worker ──► PostgreSQL + Redis + OpenSearch

Scheduler ──► Redis (enqueues jobs only)
```

---

## Data Architecture

### Database Schema (PostgreSQL + TimescaleDB)

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                           TimescaleDB                                   │
│                                                                          │
│  ┌─────────────────┐          ┌──────────────┐                           │
│  │  intel_items     │──────1:N──►│  iocs         │                        │
│  │  (hypertable)    │          │              │                           │
│  │  partitioned by  │          └──────────────┘                           │
│  │  ingested_at     │                  ▲                                  │
│  └────────┬─────────┘                  │                                  │
│           │                ┌───────────┴──────────┐                       │
│           │                │  intel_ioc_links     │                       │
│           └────────────────►│  (junction table)    │                       │
│                            └──────────────────────┘                       │
│                                                                          │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐        │
│  │  users        │  │  feed_sync_state │  │  audit_log           │        │
│  │              │  │                  │  │  (hypertable)        │        │
│  └──────┬───────┘  └──────────────────┘  └──────────────────────┘        │
│         │                                                                │
│         │  ┌──────────────────┐                                          │
│         │  │  scoring_config   │  (configurable risk scoring weights)    │
│         │  └──────────────────┘                                          │
│         │                                                                │
│  ┌──────┼────────────────────────────────────────────────────────┐       │
│  │      │  MITRE ATT&CK + Relationships                         │       │
│  │      │  ┌────────────────────┐   ┌──────────────────────┐     │       │
│  │      │  │  attack_techniques  │◄──│  intel_attack_links   │     │       │
│  │      │  │  (691 techniques)   │   │  (junction)          │     │       │
│  │      │  └────────────────────┘   └──────────────────────┘     │       │
│  │      │  ┌────────────────────┐                                │       │
│  │      │  │   relationships     │  (auto-discovered edges)      │       │
│  │      │  └────────────────────┘                                │       │
│  └──────┼────────────────────────────────────────────────────────┘       │
│         │                                                                │
│  ┌──────┼────────────────────────────────────────────────────────┐       │
│  │      │  Notifications                                         │       │
│  │      ├──►┌───────────────────┐   ┌──────────────────┐         │       │
│  │      │   │ notification_rules │──►│  notifications    │         │       │
│  │      │   │ (alert rules)      │   │  (in-app alerts) │         │       │
│  │      │   └───────────────────┘   └──────────────────┘         │       │
│  └──────┼────────────────────────────────────────────────────────┘       │
│         │                                                                │
│  ┌──────┼────────────────────────────────────────────────────────┐       │
│  │      │  Reports                                               │       │
│  │      └──►┌──────────────┐   ┌──────────────────┐              │       │
│  │          │  reports       │──►│  report_items     │              │       │
│  │          │  (JSONB content│   │  (linked intel,   │              │       │
│  │          │   + workflow)  │   │   IOCs, techniques)│              │       │
│  │          └──────────────┘   └──────────────────┘              │       │
│  └───────────────────────────────────────────────────────────────┘       │
│                                                                          │
│  Materialized Views:                                                     │
│  ├── mv_severity_distribution (30-day rollup)                            │
│  └── mv_top_risks (risk_score ≥ 70, top 100)                            │
└──────────────────────────────────────────────────────────────────────────┘
```

### Core Tables

| Table | Type | Purpose |
| ----- | ---- | ------- |
| `intel_items` | Hypertable (partitioned by `ingested_at`) | Unified intelligence records |
| `iocs` | Regular table | Deduplicated indicators of compromise |
| `intel_ioc_links` | Junction | Many-to-many intel↔IOC relationships |
| `feed_sync_state` | Regular table | Per-feed ingestion state and cursor tracking |
| `users` | Regular table | User accounts (synced from Cloudflare Zero Trust) |
| `audit_log` | Hypertable (partitioned by `created_at`) | Security audit trail |
| `scoring_config` | Regular table | Configurable risk scoring weights |
| `attack_techniques` | Regular table | MITRE ATT&CK techniques (synced from STIX) |
| `intel_attack_links` | Junction | Many-to-many intel↔technique mappings (auto/manual) |
| `relationships` | Regular table | Auto-discovered graph edges (shared IOC/CVE/technique) |
| `notification_rules` | Regular table | User-defined + system-default alert rules (threshold, feed_error, correlation) |
| `notifications` | Regular table | In-app notifications with severity, category, entity linking, and metadata |
| `reports` | Regular table | Analyst reports with JSONB content sections, status workflow, severity/TLP, template-based |
| `report_items` | Junction | Links reports to intel items, IOCs, techniques with metadata |
| `mv_severity_distribution` | Materialized view | Pre-computed 30-day severity stats |
| `mv_top_risks` | Materialized view | Pre-computed top-100 high-risk items |

### Indexing Strategy (41 indexes)

| Index | Table | Type | Purpose |
| ----- | ----- | ---- | ------- |
| `idx_users_email` | `users` | B-tree | User email lookups |
| `idx_intel_severity` | `intel_items` | B-tree | Fast severity + time filtering |
| `idx_intel_risk` | `intel_items` | B-tree | Fast risk-score ordering |
| `idx_intel_source` | `intel_items` | B-tree | Filter by source name |
| `idx_intel_feed_type` | `intel_items` | B-tree | Filter by feed type |
| `idx_intel_asset_type` | `intel_items` | B-tree | Filter by asset type |
| `idx_intel_kev` | `intel_items` | Partial B-tree | Fast KEV lookups (WHERE is_kev = TRUE) |
| `idx_intel_tags` | `intel_items` | GIN | Array containment queries on tags |
| `idx_intel_cve` | `intel_items` | GIN | Array containment queries on CVE IDs |
| `idx_intel_geo` | `intel_items` | GIN | Array containment queries on geo |
| `idx_intel_source_hash` | `intel_items` | B-tree | Deduplication by source hash |
| `idx_intel_title_trgm` | `intel_items` | GIN (trigram) | Fuzzy text search on titles |
| `idx_iocs_value` | `iocs` | B-tree | Exact IOC value lookups |
| `idx_iocs_type` | `iocs` | B-tree | Filter by IOC type |
| `idx_iocs_risk` | `iocs` | B-tree (desc) | Rank by IOC risk score |
| `idx_iocs_value_trgm` | `iocs` | GIN (trigram) | Fuzzy IOC value search |
| `idx_iocs_country_code` | `iocs` | B-tree | Filter by country (IPinfo enrichment) |
| `idx_iocs_asn` | `iocs` | B-tree | Filter by ASN (IPinfo enrichment) |
| `idx_iocs_enriched_at` | `iocs` | Partial B-tree | Find un-enriched IPs (WHERE enriched_at IS NULL) |
| `idx_attack_tactic` | `attack_techniques` | B-tree | Filter techniques by tactic phase |
| `idx_attack_parent` | `attack_techniques` | Partial B-tree | Sub-technique→parent lookups |
| `idx_attack_name_trgm` | `attack_techniques` | GIN (trigram) | Fuzzy technique name search |
| `idx_ial_technique` | `intel_attack_links` | B-tree | Fast technique→intel lookups |
| `idx_rel_source` | `relationships` | B-tree | Find edges by source entity |
| `idx_rel_target` | `relationships` | B-tree | Find edges by target entity |
| `idx_rel_type` | `relationships` | B-tree | Filter by relationship type |
| `idx_rel_confidence` | `relationships` | B-tree (desc) | Rank by confidence score |
| `idx_rel_unique_edge` | `relationships` | Unique B-tree | Prevent duplicate edges |
| `idx_nr_user` | `notification_rules` | B-tree | Rules by user |
| `idx_nr_active` | `notification_rules` | Partial B-tree | Active rules only |
| `idx_nr_type` | `notification_rules` | B-tree | Filter by rule type |
| `idx_notif_user` | `notifications` | B-tree | User notifications (time-sorted) |
| `idx_notif_unread` | `notifications` | Partial B-tree | Unread notifications (WHERE is_read = FALSE) |
| `idx_notif_category` | `notifications` | B-tree | Filter by category |
| `idx_notif_entity` | `notifications` | Partial B-tree | Entity-linked notifications |
| `idx_reports_author` | `reports` | B-tree | Reports by author |
| `idx_reports_status` | `reports` | B-tree | Filter by report status |
| `idx_reports_type` | `reports` | B-tree | Filter by report type |
| `idx_reports_created` | `reports` | B-tree (desc) | Recent reports first |
| `idx_reports_tags` | `reports` | GIN | Array containment on report tags |
| `idx_report_items_report` | `report_items` | B-tree | Items by report |
| `idx_report_items_type` | `report_items` | B-tree | Items by type + ID |
| `idx_mv_severity` | `mv_severity_distribution` | Unique B-tree | MV refresh key |
| `idx_mv_top_risks` | `mv_top_risks` | Unique B-tree | MV refresh key |

### OpenSearch Index

- Index: `intel-items`
- Mapping: `opensearch/intel-items-mapping.json`
- Used for: full-text IOC search, faceted queries, analytics aggregations

---

## API Architecture

### Layer Pattern

```text
Route Handler (thin) ──► Service Layer (business logic) ──► Data Layer (ORM / cache)
         │                        │                              │
         ▼                        ▼                              ▼
   Pydantic schema          Scoring engine              SQLAlchemy async
   validation               AI summarization            Redis cache
   Auth middleware           Feed normalization          OpenSearch client
```

### Module Breakdown

| Layer | Path | Responsibility |
| ----- | ---- | -------------- |
| **Core** | `api/app/core/` | Config, database pool, Redis client, OpenSearch client, structured logging |
| **Middleware** | `api/app/middleware/` | Auth (JWT session + Cloudflare JWT verify), audit logging |
| **Models** | `api/app/models/` | SQLAlchemy ORM model definitions |
| **Schemas** | `api/app/schemas/` | Pydantic v2 request/response schemas |
| **Routes** | `api/app/routes/` | Thin route handlers — validate, delegate to service, return response |
| **Services** | `api/app/services/` | All business logic: auth, database access, scoring, search, AI, export, MITRE ATT&CK, graph, notifications, reports, domain config, live internet lookup, feed connectors |
| **Feeds** | `api/app/services/feeds/` | Plugin-based feed connectors (inherit from `BaseFeedConnector`) |

### Endpoint Map (63 endpoints across 11 route files)

| Method | Endpoint | Auth | Handler | Service |
| ------ | -------- | ---- | ------- | ------- |
| `GET` | `/api/v1/health` | None | `routes/health.py` | — |
| `GET` | `/api/v1/status/bar` | None | `routes/health.py` | Cached health + quick intel stats for header |
| `GET` | `/api/v1/auth/config` | None | `routes/auth.py` | `services/auth.py` |
| `POST` | `/api/v1/auth/login` | None | `routes/auth.py` | `services/auth.py` |
| `POST` | `/api/v1/auth/logout` | Cookie | `routes/auth.py` | `services/auth.py` |
| `GET` | `/api/v1/auth/session` | Cookie | `routes/auth.py` | `services/auth.py` |
| `POST` | `/api/v1/auth/google` | None | `routes/auth.py` | `services/auth.py` |
| `GET` | `/api/v1/me` | Any | `routes/admin.py` | — |
| `GET` | `/api/v1/users` | Admin | `routes/admin.py` | — |
| `PATCH` | `/api/v1/users/{user_id}` | Admin | `routes/admin.py` | — |
| `GET` | `/api/v1/dashboard` | Viewer | `routes/dashboard.py` | `services/database.py` |
| `GET` | `/api/v1/intel` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/intel/export` | Viewer | `routes/intel.py` | `services/export.py` |
| `GET` | `/api/v1/intel/{id}` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/intel/{id}/enrichment` | Viewer | `routes/intel.py` | `services/ai.py` |
| `GET` | `/api/v1/intel/{id}/related` | Viewer | `routes/intel.py` | `services/database.py` |
| `POST` | `/api/v1/search` | Viewer | `routes/search.py` | `services/search.py` |
| `GET` | `/api/v1/search/stats` | Viewer | `routes/search.py` | `services/search.py` |
| `POST` | `/api/v1/search/live-lookup` | Viewer | `routes/search.py` | `services/live_lookup.py` |
| `GET` | `/api/v1/feeds/status` | Viewer | `routes/admin.py` | `services/database.py` |
| `POST` | `/api/v1/feeds/{feed_name}/trigger` | Admin | `routes/admin.py` | `services/feeds/*` |
| `POST` | `/api/v1/feeds/trigger-all` | Admin | `routes/admin.py` | `services/feeds/*` |
| `GET` | `/api/v1/setup/config` | Admin | `routes/admin.py` | `services/domain.py` |
| `GET` | `/api/v1/setup/status` | Admin | `routes/admin.py` | `services/domain.py` |
| `GET` | `/api/v1/techniques` | Viewer | `routes/techniques.py` | `services/mitre.py` |
| `GET` | `/api/v1/techniques/matrix` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/techniques/{id}` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/techniques/intel/{item_id}/techniques` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/graph/explore` | Viewer | `routes/graph.py` | `services/graph.py` |
| `GET` | `/api/v1/graph/related/{id}` | Viewer | `routes/graph.py` | `services/graph.py` |
| `GET` | `/api/v1/graph/stats` | Viewer | `routes/graph.py` | `services/graph.py` |
| `GET` | `/api/v1/notifications` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `GET` | `/api/v1/notifications/unread-count` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `GET` | `/api/v1/notifications/stats` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `POST` | `/api/v1/notifications/mark-read` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `POST` | `/api/v1/notifications/mark-all-read` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `DELETE` | `/api/v1/notifications/{id}` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `DELETE` | `/api/v1/notifications` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `GET` | `/api/v1/notifications/rules` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `POST` | `/api/v1/notifications/rules` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `PUT` | `/api/v1/notifications/rules/{id}` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `DELETE` | `/api/v1/notifications/rules/{id}` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `POST` | `/api/v1/notifications/rules/{id}/toggle` | Viewer | `routes/notifications.py` | `services/notifications.py` |
| `GET` | `/api/v1/reports` | Viewer | `routes/reports.py` | `services/reports.py` |
| `POST` | `/api/v1/reports` | Analyst | `routes/reports.py` | `services/reports.py` |
| `GET` | `/api/v1/reports/templates` | Viewer | `routes/reports.py` | `services/reports.py` |
| `GET` | `/api/v1/reports/stats` | Viewer | `routes/reports.py` | `services/reports.py` |
| `GET` | `/api/v1/reports/{id}` | Viewer | `routes/reports.py` | `services/reports.py` |
| `PUT` | `/api/v1/reports/{id}` | Analyst | `routes/reports.py` | `services/reports.py` |
| `DELETE` | `/api/v1/reports/{id}` | Analyst | `routes/reports.py` | `services/reports.py` |
| `POST` | `/api/v1/reports/{id}/items` | Analyst | `routes/reports.py` | `services/reports.py` |
| `DELETE` | `/api/v1/reports/{id}/items/{item_id}` | Analyst | `routes/reports.py` | `services/reports.py` |
| `POST` | `/api/v1/reports/{id}/ai-summary` | Analyst | `routes/reports.py` | `services/reports.py` |
| `POST` | `/api/v1/reports/{id}/ai-generate` | Analyst | `routes/reports.py` | `services/reports.py`, `services/research.py` |
| `GET` | `/api/v1/reports/{id}/export?format=` | Viewer | `routes/reports.py` | `services/reports.py` |
| `GET` | `/api/v1/cases` | Viewer | `routes/cases.py` | `services/cases.py` |
| `GET` | `/api/v1/cases/stats` | Viewer | `routes/cases.py` | `services/cases.py` |
| `GET` | `/api/v1/cases/assignees` | Viewer | `routes/cases.py` | `services/cases.py` |
| `GET` | `/api/v1/cases/export` | Viewer | `routes/cases.py` | `services/cases.py` |
| `GET` | `/api/v1/cases/{id}` | Viewer | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases` | Analyst | `routes/cases.py` | `services/cases.py` |
| `PUT` | `/api/v1/cases/{id}` | Analyst | `routes/cases.py` | `services/cases.py` |
| `DELETE` | `/api/v1/cases/{id}` | Analyst | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases/{id}/comments` | Analyst | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases/{id}/items` | Analyst | `routes/cases.py` | `services/cases.py` |
| `DELETE` | `/api/v1/cases/{id}/items/{item_id}` | Analyst | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases/bulk/status` | Analyst | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases/bulk/assign` | Analyst | `routes/cases.py` | `services/cases.py` |
| `POST` | `/api/v1/cases/bulk/delete` | Analyst | `routes/cases.py` | `services/cases.py` |

---

## Frontend Architecture

### Stack

| Concern | Technology |
| ------- | ---------- |
| Framework | Next.js 14 (App Router) |
| Language | TypeScript (strict) |
| Styling | Tailwind CSS 3.4 + CSS variables |
| UI primitives | shadcn/ui (Card, Badge, Button, Input, Tabs) |
| Charts | Recharts 2.12 (DonutChart, TrendLineChart, HorizontalBarChart) |
| State | Zustand 4.5 (single store, no prop drilling) |
| Icons | Lucide React |
| API client | Custom fetch wrapper with error handling |

### Page Layout

```text
┌──────────────────────────────────────────────────┐
│  Sidebar               │  Header Bar             │
│  ┌────────────────┐    │  ┌───────────────────┐  │
│  │ Logo + Brand   │    │  │ Search │ Live │ 🔔 │  │
│  │ Overview       │    │  │        │      │  👤 │  │
│  │  Dashboard     │    │  └───────────────────┘  │
│  │  Threat Feed   │    ├─────────────────────────│
│  │ Investigation  │    │                         │
│  │  Intel Items   │    │   Page Content           │
│  │  Reports       │    │                         │
│  │  Investigate   │    │                         │
│  │  ATT&CK Map   │    │   (cards, charts,       │
│  │  IOC Search    │    │    tables, filters)     │
│  │  IOC Database  │    │                         │
│  │ Analytics      │    │                         │
│  │  Analytics     │    │                         │
│  │  Geo View      │    │                         │
│  │ System         │    │                         │
│  │  Feed Status   │    │                         │
│  │  Settings      │    │                         │
│  └────────────────┘    │                         │
└──────────────────────────────────────────────────┘
```

### Component Hierarchy (24 components, 16 pages)

```text
app/layout.tsx (root HTML, dark class)
├── login/page.tsx (IntelWatch branded login — SSO or dev bypass)
└── (app)/layout.tsx (AuthGuard + Sidebar + Header + HeaderStatusBar + NotificationBell + ErrorBoundary + main area)
    ├── dashboard/page.tsx
    │   ├── StatCard ×6 (with optional tooltip)
    │   ├── ThreatLevelBar
    │   ├── DonutChart ×2
    │   ├── HorizontalBarChart
    │   ├── RankedDataList ×2
    │   ├── FeedStatusPanel
    │   └── Data Table
    ├── threats/page.tsx
    ├── intel/page.tsx → intel/[id]/page.tsx
    │   ├── IntelCard (with DataTooltip on risk score)
    │   ├── StructuredIntelCards (Overview tab)
    │   ├── EnhancedTimelineEvent (Timeline tab — color-coded cards, event type legend)
    │   └── IOCDetailRow (IOCs tab — expandable rows with InternetDB/EPSS enrichment)
    ├── investigate/page.tsx (GraphExplorer)
    ├── techniques/page.tsx (CoverageRing donut + DetectionGapsCard + ATTACKMatrix)
    ├── search/page.tsx (Enhanced: sortable table, debounced search, type/severity/feed filter pills, donut+bar charts, VT/Shodan enrichment slide-over, copy-to-clipboard)
    ├── iocs/page.tsx (IOC Database — table, stats, VT/Shodan enrichment panel + stored InternetDB/EPSS/IPinfo context)
    ├── analytics/page.tsx
    ├── reports/page.tsx → reports/new/page.tsx, reports/[id]/page.tsx
    ├── geo/page.tsx (5-tab layout: Countries, Continents, Networks, Industries, Intel Geo)
    ├── feeds/page.tsx
    └── settings/page.tsx

Shared Components (14 root + 4 charts + 6 ui primitives):
├── AuthGuard (route protection wrapper)
├── ErrorBoundary / WidgetErrorBoundary (page + widget error recovery)
├── EmptyState (no-data guidance per Instruction.md)
├── Loading (skeleton-based page loading, no spinners)
├── NotificationBell (header bell + dropdown via React Portal)
├── HeaderStatusBar (10-widget command strip — polls /status/bar every 30s)
│   ├── System Health pill (OK/Degraded with service tooltip)
│   ├── Threat Level Gauge (Low/Medium/High/Critical from avg risk score)
│   ├── Intel Counter (total + 24h delta)
│   ├── Crit/High badge (combined count)
│   ├── Active CVEs (CISA KEV count)
│   ├── Feed Activity Sparkline (SVG polyline, 24 hourly bins)
│   ├── Last Feed timestamp (timeAgo)
│   ├── ATT&CK Coverage (% linked + 7-day trend arrow ↑/↓/—, links to /techniques)
│   ├── Search Stats (today count from audit_log)
│   └── Quick Actions — Run All Feeds (admin-only)
├── Sidebar (4-section navigation)
├── StatCard, IntelCard, FeedStatusPanel, RankedDataList, ThreatLevelBar
├── GraphExplorer (SVG force-directed graph)
├── ATTACKMatrix (MITRE ATT&CK heatmap grid — per-tactic coverage bars,
│       rich severity tooltips w/ SeverityMicroBar, ATT&CK Navigator JSON export)
├── Pagination (page/pages/onPageChange)
├── Tooltip / DataTooltip (Radix UI — score/status metadata)
├── charts/ — DonutChart, HorizontalBarChart, TrendLineChart
└── ui/ — badge, button, card, input, tabs, tooltip (shadcn/ui primitives)
```

---

## Worker Architecture

### Job Processing

```text
Scheduler (APScheduler)
    │
    │  enqueue every N minutes
    ▼
Redis Queue (RQ)
    │
    │  dequeue
    ▼
Worker Process
    │
    ├── Feed Connector (fetch raw data)
    │       ▼
    ├── Normalizer (convert to intel_items schema)
    │       ▼
    ├── Scorer (compute risk_score)
    │       ▼
    ├── PostgreSQL (bulk upsert)
    │       ▼
    ├── OpenSearch (bulk index)
    │       ▼
    └── AI Summarizer (optional — async enrichment)
```

### Feed Connector Pattern

All connectors inherit from `BaseFeedConnector`:

```python
class BaseFeedConnector(ABC):
    FEED_NAME: str
    FEED_URL: str
    
    @abstractmethod
    async def fetch(self) -> list[dict]: ...
    
    @abstractmethod  
    async def normalize(self, raw: list[dict]) -> list[IntelItemCreate]: ...
    
    async def sync(self):
        raw = await self.fetch()
        items = await self.normalize(raw)
        await self.store(items)  # bulk upsert + index
```

### Schedule (19 jobs)

| Job | Interval | Queue | Priority |
| --- | -------- | ----- | -------- |
| CISA KEV | 60 min | high | Critical (exploited vulns) |
| URLhaus | 30 min | high | High (active malicious URLs) |
| ThreatFox | 30 min | high | High (malware C2/botnet IOCs) |
| NVD | 15 min | default | Medium (new CVEs) |
| AbuseIPDB | 15 min | default | Medium (IP reputation) |
| VirusTotal | 60 min | default | Medium (malware hashes, URLs) |
| MalwareBazaar | 30 min | default | Medium (malware file hashes) |
| OTX | 30 min | low | Medium (campaign intel) |
| Shodan | 12 hrs | low | Medium (exposed services) |
| Dashboard Refresh | 2 min | low | Low (refresh materialized views) |
| AI Summaries | 5 min | low | Low (enrichment pass) |
| ATT&CK Sync | 24 hrs | low | Low (refresh STIX data) |
| ATT&CK Mapping | 10 min | low | Low (auto-map intel→techniques) |
| Relationship Builder | 15 min | low | Low (discover shared IOC/CVE/technique edges) |
| IOC Extraction | 10 min | low | Low (extract IOCs from intel items) |
| Notification Eval | 5 min | low | Low (evaluate rules, create in-app alerts) |
| IPinfo Enrichment | 10 min | low | Low (enrich IP IOCs with ASN/geo data) |
| Shodan InternetDB | 10 min | low | Low (enrich IPs with ports/vulns/hostnames) |
| FIRST EPSS Scoring | 24 hrs | low | Low (CVE exploit probability scoring) |

### Scheduler Lifecycle

The scheduler registers `SIGTERM` + `atexit` handlers that **cancel all scheduled jobs and remove stale Redis instance keys** on shutdown. This prevents ghost jobs after `docker compose restart` or `redis-cli FLUSHALL`. On next startup, `setup_schedules()` re-registers all 19 jobs cleanly.

---

## Security Architecture

### Authentication Flow

```text
┌─ Production (Cloudflare Zero Trust SSO) ─────────────────────────┐
│                                                                    │
│  Browser ──► Cloudflare Access ──► SSO Provider (Google)          │
│                    │                                               │
│                    ▼                                               │
│  CF headers (Cf-Access-Jwt-Assertion + email)                     │
│                    │                                               │
│                    ▼                                               │
│  POST /api/v1/auth/login ──► verify CF JWT ──► create session     │
│                    │                                               │
│                    ▼                                               │
│  Set HttpOnly cookie (iw_session) ──► JWT with user + role        │
└────────────────────────────────────────────────────────────────────┘

┌─ Development (Bypass Mode) ──────────────────────────────────────┐
│                                                                    │
│  Browser ──► /login page ──► "Sign in (Dev Mode)" button          │
│                    │                                               │
│                    ▼                                               │
│  POST /api/v1/auth/login ──► auto-create dev admin user           │
│                    │                                               │
│                    ▼                                               │
│  Set HttpOnly cookie (iw_session) ──► JWT with dev user           │
└────────────────────────────────────────────────────────────────────┘

Session Management:
- JWT tokens stored as HttpOnly, Secure, SameSite cookies
- Server-side session tracking in Redis (revocable)
- Configurable TTL (default: 8 hours)
- Logout revokes session in Redis + clears cookie
```

### RBAC Roles

| Role | Permissions |
| ---- | ----------- |
| `viewer` | Read dashboard, intel, search, techniques, graph, reports, notifications, feed status, export intel |
| `analyst` | Viewer + create/update/delete reports, manage report items, generate AI summaries |
| `admin` | Analyst + trigger feeds, manage users, setup config/status |

### Security Layers

| Layer | Implementation |
| ----- | -------------- |
| Network | Cloudflare Tunnel (no exposed ports to internet) |
| Auth | JWT session cookies + Cloudflare Zero Trust SSO fallback |
| Sessions | Redis-backed, revocable, HttpOnly cookies |
| RBAC | Role-based decorators on route handlers |
| Input | Pydantic v2 strict validation on all endpoints |
| Queries | SQLAlchemy ORM — parameterized only |
| Rate limiting | Configurable per-endpoint rate limits |
| Audit | All auth events + mutations logged to `audit_log` hypertable |
| Secrets | Environment variables only — never in code |

---

## Deployment Architecture

### Production

```text
VPS (2 vCPU, 4 GB RAM minimum)
    │
    ├── Docker Compose (7 services)
    ├── Cloudflare Tunnel (Argo) → intelwatch.trendsmap.in
    ├── Let's Encrypt via Cloudflare (automatic HTTPS)
    └── GitHub Actions CI/CD (build → push → SSH deploy)
```

### CI/CD Pipeline

```text
Push to main
    ▼
GitHub Actions
    ├── Lint (ruff + tsc)
    ├── Build Docker images (API, UI, Worker)
    ├── Push to GHCR
    └── SSH deploy: git pull + docker compose up -d
```

---

## Codebase Metrics

> Last updated: **2026-03-03** (Structured AI Analysis + Unified StructuredIntelCards)

### Lines of Code by Category

| Category | Lines | Files | Description |
| -------- | -----: | -----: | ----------- |
| Python (API + Worker) | 11,350 | 51 | FastAPI routes, services, models, schemas, feeds, worker tasks, live lookup |
| TypeScript/TSX (UI) | 14,300 | 50 | Next.js pages, components, store, types, API client |
| Markdown (Docs) | 2,747 | 7 | Architecture, roadmap, instructions, integration, technology |
| Config (JSON/YAML/CSS/TOML) | 517 | 8 | package.json, tailwind, tsconfig, docker-compose, OpenSearch mapping |
| SQL (Schema + Migrations) | 468 | 3 | PostgreSQL + TimescaleDB DDL, indexes, materialized views |
| Docker | 262 | 5 | Multi-stage Dockerfiles (API, UI, Worker), compose files |
| **TOTAL** | **~20,600** | **~124** | |

### Documentation Breakdown

| File | Lines | Content |
| ---- | -----: | ------- |
| docs/ROADMAP.md | 784 | 7-phase feature roadmap with implementation details |
| docs/Instruction.md | 514 | Development rules, UI guidelines, mandatory checklists |
| docs/ARCHITECTURE.md | ~647 | System architecture, DB schema (41 indexes), API endpoints (47) |
| docs/INTEGRATION.md | 382 | Feed connector specs, API integration patterns |
| docs/TECHNOLOGY.md | 218 | Tech stack decisions and rationale |
| README.md | 157 | Project overview, quick start, deployment |
| docs/WORKFLOW.md | 134 | Git workflow, CI/CD, deployment procedures |

### Growth Milestones

| Date | Milestone | Total LOC |
| ---- | --------- | --------: |
| 2026-02-23 | Initial platform (7 feeds, dashboard, search) | ~8,500 |
| 2026-02-26 | Phase 1.1 — MITRE ATT&CK (691 techniques, matrix UI) | ~12,000 |
| 2026-02-27 | Phase 1.2 — Relationship Graph (3,875 edges, graph explorer) | ~16,400 |
| 2026-02-28 | Phase 1.3 — Notifications & Alerting (rules, bell, 12 endpoints) | ~17,500 |
| 2026-02-28 | Phase 1.4 — Report Generation (templates, AI summary, export) | ~18,800 |
| 2026-02-28 | Phase 1.5 — VirusTotal & Shodan Connectors | ~19,315 |
| 2026-03-01 | Phase 1.6 — AI Web Research & Enhanced Report Sections | ~19,800 |
| 2026-03-02 | Live Internet Lookup (12+ external API sources, AI summary) | ~20,500 |
| 2026-03-03 | Structured AI Analysis + Unified StructuredIntelCards | ~20,600 |
| 2026-03-07 | Cross-Enrichment Engine — 8 features, 14 API endpoints, 2 new pages | ~22,800 |

---

## Cross-Enrichment Engine (v1.8)

> Added 2026-03-07. Automatically links news intelligence, campaigns, threat actors, IOCs, and ATT&CK techniques across all platform surfaces.

### Architecture

```text
news_items ──┐
             ├──► cross_enrichment.py ──► 14 API endpoints ──► 6 enriched pages + 2 new pages
campaigns ───┤       (8 function groups)         ▲
techniques ──┤                                   │
products ────┘                              Redis cache (2-5 min TTL)
```

### Backend Service: `api/app/services/cross_enrichment.py` (684 lines)

| # | Function Group | SQL Complexity | Cached | TTL |
|---|---------------|---------------|--------|-----|
| 1 | Dashboard Enrichment | 5 queries (campaigns, actors, sectors, CVEs, trend) | ✓ | 120s |
| 2 | Intel Batch Cross-Link | 2 queries (item CVEs/products → news) | ✓ | 120s |
| 3 | IOC Campaign Membership | 1 query (ILIKE match against news content) | — | — |
| 4 | Technique Usage Heatmap | 1 query (UNNEST techniques → campaigns/actors) | ✓ | 300s |
| 5 | Threat Velocity | 2 queries (3-day vs 7-day window, CVEs + actors) | ✓ | 300s |
| 6 | Org Exposure Scoring | 2 queries (sector campaigns + tech stack products) | ✓ | 300s |
| 7 | Detection Rule Library | 3 functions (query, coverage stats, sync from news) | — | — |
| 8 | Briefing Data Collection | Aggregates all above + stats for AI generation | — | — |

### API Routes: `api/app/routes/enrichment.py` (290 lines, 14 endpoints)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/enrichment/dashboard` | GET | viewer | Active campaigns, top actors, sector threats, trending CVEs |
| `/enrichment/intel-context` | POST | viewer | Campaign/actor context for single intel item |
| `/enrichment/intel-batch` | POST | viewer | Batch enrich multiple intel items |
| `/enrichment/ioc-context` | GET | viewer | Campaign membership for IOC value |
| `/enrichment/technique-usage` | GET | viewer | ATT&CK technique usage heatmap data |
| `/enrichment/technique-detail` | GET | viewer | Detailed technique enrichment |
| `/enrichment/velocity` | GET | viewer | Accelerating threat entity mentions |
| `/enrichment/org-exposure` | POST | viewer | Personalized org threat exposure score |
| `/enrichment/detection-rules` | GET | viewer | Query detection rule library |
| `/enrichment/detection-coverage` | GET | viewer | Rule coverage statistics |
| `/enrichment/detection-rules/sync` | POST | viewer | Extract rules from news into library |
| `/enrichment/briefing-data` | GET | viewer | Raw data for briefing generation |
| `/enrichment/generate-briefing` | POST | viewer | Generate AI threat briefing |
| `/enrichment/briefings` | GET | viewer | List past briefings |

### Database: 2 new tables (`migrations/20260307_enrichment_features.sql`)

**`threat_briefings`** — AI-generated periodic threat intelligence summaries
- period (daily/weekly), period_start/end, title, executive_summary
- key_campaigns JSONB, key_vulnerabilities JSONB, key_actors JSONB
- sector_threats JSONB, stats JSONB, recommendations TEXT[], raw_data JSONB

**`detection_rules`** — Aggregated YARA/KQL/Sigma rule library
- rule_type, name, content, source_news_id FK
- campaign_name, technique_ids[], cve_ids[], severity, quality_score (0-100)
- GIN indexes on technique_ids and cve_ids for fast lookups

### Frontend: 6 enriched pages + 2 new pages

| Page | Enrichment Added |
|------|-----------------|
| Dashboard | Active Campaigns card, Threat Velocity card, Sector Threat Map card |
| Intel Feed | Campaign/actor badges on each IntelCard via batch enrichment |
| IOC Database | Campaign Membership panel in enrichment sidebar |
| MITRE Techniques | Active Usage Heatmap (30-day, intensity-colored grid) |
| Settings | Organization Profile section (sectors, regions, tech stack, exposure score) |
| **NEW: Detections** | `/detections` — YARA/Sigma/KQL rule library with filters, copy, sync |
| **NEW: Briefings** | `/briefings` — AI-powered weekly threat briefing generation |

### TypeScript Types: 15 interfaces in `ui/src/types/index.ts`

ActiveCampaign, TopThreatActor, SectorThreat, TrendingCVE, ThreatVelocityItem,
DashboardEnrichment, IntelCampaignContext, IntelBatchEnrichment, IOCCampaignContext,
TechniqueUsageItem, TechniqueDetailEnrichment, OrgExposure, DetectionRule,
DetectionCoverage, ThreatBriefingSummary

---

## Planned Features (Backlog)

> Items below are approved concepts for future implementation. Some have partial coverage via the Cross-Enrichment Engine (v1.8).

### Domain Impersonation Monitoring
*Status: Not implemented. No overlap with cross-enrichment.*

Detect lookalike / typosquat domains targeting a configured list of protected brands or assets.

- **Phishing domain detection** — periodic scan of newly registered domains (e.g. via Certificate Transparency logs, WHOIS feeds, DNSTwist) for permutations of monitored domains
- **Similarity scoring** — Levenshtein / homoglyph / IDN analysis to rank impersonation likelihood
- **Alert integration** — high-confidence matches auto-create notifications and appear on the dashboard
- **Takedown tracking** — status field (detected → reported → taken down) with timeline
- **UI** — dedicated "Domain Watch" page: add protected domains, view alerts, similarity heatmap

### Custom Campaign / Conflict Monitoring
*Status: Partially addressed. Cross-enrichment provides campaign tracking across news, dashboard campaign cards, and intel campaign badges. Missing: user-defined campaigns, custom timeline, collaboration features.*

Track specific threat campaigns, military/cyber conflicts, or coordinated operations over time.

- **Campaign workspace** — user-defined campaign with name, description, date range, tags, MITRE TTPs
- **Auto-collection rules** — keyword/IOC/TTP filters that auto-link new intel items to the campaign
- **Campaign timeline** — chronological event view aggregating all linked intel, IOCs, and ATT&CK techniques
- **Collaboration** — shared campaign notes, analyst annotations, TLP-tagged sharing
- **Templates** — preset campaign profiles for common scenarios (ransomware wave, APT tracking, conflict cyber ops)

### Global Event Intelligence
*Status: Partially addressed. Threat Velocity tracking monitors entity acceleration. AI Briefings generate situational awareness summaries. Missing: user-defined events, multi-source OSINT, geo overlay.*

Real-time monitoring and correlation for large-scale global events (natural disasters, geopolitical crises, major cyber incidents).

- **Event creation** — define an event with region, timeframe, and keyword watchlist
- **Multi-source aggregation** — pull from all existing feeds + optional RSS / Twitter / Telegram OSINT channels
- **Impact correlation** — map event timeline against threat activity spikes, IOC surges, and CVE exploitation
- **Geo overlay** — integrate with Geo View to show affected regions and threat actor origins
- **Briefing generator** — one-click AI-generated situational awareness briefing for the event

---

## Revision History

| Date | Change |
| ---- | ------ |
| 2026-03-07 | **Cross-Enrichment Engine (v1.8)** — 8-feature cross-enrichment engine linking news intelligence across all platform entities. Backend: `cross_enrichment.py` (684 lines, 8 function groups), `enrichment.py` (290 lines, 14 API endpoints), 2 new DB tables (`threat_briefings`, `detection_rules`), 2 ORM models. Frontend: 15 TypeScript types, 15 API client functions, enrichment widgets on 5 existing pages (Dashboard, Intel, IOCs, Techniques, Settings), 2 new pages (`/detections` — YARA/Sigma/KQL rule library with sync/filter/copy; `/briefings` — AI-powered weekly briefing generation). Features: active campaign tracking, threat velocity monitoring, sector threat mapping, intel campaign/actor badges, IOC campaign membership, MITRE usage heatmap, org profile exposure scoring (0-100), detection rule auto-extraction from news, AI threat briefing generation via `chat_completion()`. Bug fixes: list_briefings missing period fields, severity filter on detection-rules, quality_score display × 100 bug, briefing stats key mismatch, dead code in sector_threat_map SQL. |
| 2026-03-05 | Phase 2.1 Case Management — P2 Improvements: **Status transition validation** — enforced allowed state machine transitions (new→in_progress/pending/closed, etc.), 422 error on invalid transitions, `ALLOWED_TRANSITIONS` constant in frontend for smart status dropdown. **Expanded filters** — severity, TLP, date range (date_from/date_to), and tag filtering on cases list; PostgreSQL `func.any()` for ARRAY tag filter. **Bulk operations** — bulk status update, bulk assign, bulk delete endpoints (`POST /cases/bulk/status`, `/bulk/assign`, `/bulk/delete`); UI bulk action bar with select-all, per-row checkboxes. **Export** — JSON and CSV export (`GET /cases/export?format=json|csv&ids=...`), download button in UI header. **Assignee selector** — `GET /cases/assignees` endpoint (admin+analyst users), assignee dropdown in create modal and edit mode. **Edit severity/TLP/tags** — full editing of severity, TLP, tags, and assignee in case detail page edit mode. **Linked items clickable** — intel items link to `/intel/{id}`, IOCs link to `/search?q={value}`. |
| 2026-03-05 | Phase 2.1 Case Management — P1 Improvements: severity/TLP/tags in create modal, duplicate item detection (409), activity logging on item removal, owner/assignee email on list view (batch loaded), activity user emails (batch loaded), error handling on delete and add item. |
| 2026-03-04 | UI Improvements Phase 7: **Intel Detail Page** — new IOCs tab showing linked indicators with InternetDB enrichment (ports, vulns, CPEs, hostnames, tags), EPSS scores, IPinfo geolocation; enhanced Timeline tab with event type legend, color-coded cards, relative dates, source badges; improved Threat Actor section with motivation emoji icons, confidence coloring, "Hunt" search link, technique counts; improved Notable Campaigns section with visual timeline, severity-based dots, Impact Assessment box. New API endpoint `GET /intel/{id}/iocs` (joins IOC+IntelIOCLink with enrichment data). **IOC Database Page** — enrichment side panel now shows stored IPinfo (country, ASN, network), InternetDB (ports, vulns, CVE links to NVD, technologies/CPEs, hostnames, tags), and EPSS scores with probability bar before VT/Shodan on-demand results. **Geo View Page** — complete overhaul from single-source to 5-tab layout: Countries (flag grid + donut + AI threat geography), Continents (emoji progress bars), Networks (ASN bar chart), Industries (AI-enriched targeting), Intel Geo (original region data with severity pills + detail drill-down); uses `getDashboardInsights()` + `getIOCStats()` for comprehensive data. |
| 2026-03-03 | ATT&CK Page Improvements: **Status bar** — ATT&CK coverage pill now shows 7-day trend arrow (↑/↓/—) via new `attack_coverage_prev_pct` field (SQL lookback on `intel_attack_links.created_at`); cache key bumped to v3. **ATT&CK page** — new `CoverageRing` SVG donut chart (animated, color-coded by %), new `DetectionGapsCard` showing top 20 unmapped high-priority techniques (initial-access, execution, persistence, priv-esc, defense-evasion, lateral-movement, impact). **ATT&CK matrix** — per-tactic mini coverage bars (mapped/total, 3-tier color), rich hover tooltips with `SeverityMicroBar` stacked severity breakdown, ATT&CK Navigator v4.5 JSON layer export (download button). API: severity counts via `literal_column()` ENUM casts in `case()`, `DetectionGap` schema, `mapped`/`total` per tactic. |
| 2026-03-03 | Structured AI Analysis: replaced plain-text `_ai_summarize()` with `_ai_analyze()` returning structured JSON (summary, threat_actors, timeline, affected_products, fix_remediation, known_breaches, key_findings); date-descending sort on live lookup results; `ai_analysis: dict` in `LiveLookupResponse` schema |
| 2026-03-03 | Unified StructuredIntelCards: new shared component `StructuredIntelCards.tsx` (~220 lines) with `full`/`compact` variants — color-coded cards (purple summary, orange TAs, cyan products, red breaches, emerald fix, blue timeline, amber findings); integrated into Search page (replaced inline JSX), Intel Detail overview tab (maps enrichment data), InsightDetailModal (maps aggregated stats), Threats page (unified badge scheme) |
| 2026-03-02 | Live Internet Lookup: `services/live_lookup.py` (832 lines) — type-aware external API querying (NVD, AbuseIPDB, VirusTotal, Shodan, URLhaus, OTX, CISA KEV, DuckDuckGo); IOC auto-detection routes to appropriate sources (CVE→NVD+KEV+Web, IP→AbuseIPDB+VT+Shodan, Domain→VT+Shodan+Web, Hash→VT, URL→VT+URLhaus, Email→Web, Keyword→NVD+OTX+Web); AI summary synthesis via Groq; Redis caching (10 min TTL); `POST /search/live-lookup` endpoint; search page "Search Internet" button (zero-results + results header); live results display with source badges, AI summary card, severity-colored result cards, risk scores, references, CVE IDs, ports, tags |
| 2026-03-02 | Enhanced Search Page: fix ResponseValidationError (optional `updated_at`), add `GET /search/stats` aggregation endpoint, sortable columns (7 fields), debounced search (400ms), type/severity/feed filter pills from live stats, collapsible donut+bar charts, copy-to-clipboard, VT/Shodan enrichment slide-over panel with backdrop, intel summary card, empty-state example queries + feature highlight cards; worker+admin reindex now index `updated_at`, `ai_summary` |
| 2026-03-02 | Enhanced status bar: 10 widgets (health, threat gauge, intel count, crit/high, KEV, sparkline, last feed, ATT&CK %, search stats, admin quick actions); API extended with avg_risk_score, kev_count, attack_coverage_pct, searches_today, sparkline (24h hourly bins via generate_series); data-driven Live indicator; theme toggle; scheduler auto-cleanup on SIGTERM/atexit |
| 2026-03-01 | Phase 1.6 AI Web Research: `services/research.py` (NVD, OTX, DuckDuckGo, OpenSearch live research), enhanced templates (11 sections: timeline, confirmation, exploitability, PoC availability, impacted tech, affected orgs), `generate_ai_sections` now research-backed |
| 2026-03-01 | Intel pages enhancement: advanced filters (KEV, exploit, asset type, keyword search, sort direction), enrichment endpoints (`/intel/{id}/enrichment` AI analysis, `/intel/{id}/related` DB overlap), detail page 5-tab redesign (Overview, ATT&CK, Timeline, Remediation, Related), IntelCard compact data row |
| 2026-03-02 | Dashboard fixes & competitive enrichments: Reports StatCard href fix (`/intel`→`/reports`), count inflation fix (`count(*)`→`count(DISTINCT id)` in insight queries), expanded TA/malware tag patterns (+DPRK, BeaverTail, luminousmoth, clearfake, plugx, etc. — 18 TAs up from 5), new sections: Intel Ingestion Trend (30-day area chart), Threat Geography (top 15 regions), Target Industries (top 15 sectors), Attack Techniques (phishing, credential theft, etc.), Exploit/EPSS Summary bar (exploit %, KEV %, avg EPSS, high EPSS count) |
| 2026-02-28 | Multi-format export: PDF (reportlab + TLP watermark), STIX 2.1 Bundle, HTML (dark-theme), CSV; UI export dropdown with 5 format options; updated codebase metrics |
| 2026-02-28 | Phase 1.4 Report Generation: reports + report_items tables, 11 report endpoints, 3 UI pages, templates, AI summary, multi-format export (PDF, STIX 2.1, HTML, CSV, Markdown) |
| 2026-02-28 | Phase 1.3 Notifications & Alerting: notification_rules + notifications tables, 12 notification endpoints, NotificationBell component, worker eval task |
| 2026-02-28 | Post-audit fixes: OpenSearch dedup (834K→3,944), ATT&CK keyword precision, skeleton loaders, ErrorBoundary, Tooltip system |
| 2026-02-28 | Phase 1.2 Relationship Graph; added Codebase Metrics section |
| 2026-02-24 | Production domain set to intelwatch.trendsmap.in; simplified login docs |
| 2026-02-24 | Renamed to IntelWatch; added VirusTotal & Shodan API key support; login testing verified |
| 2026-02-23 | Renamed to IntelWatch TI Platform; added auth architecture (JWT sessions, login flow, auth guard) |
| 2026-02-23 | Initial architecture document extracted from README |
