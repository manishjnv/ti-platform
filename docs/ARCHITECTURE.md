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

```
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
|---------|-------------|-----------|----------------|------|
| **UI** | `ui` | Next.js 14, TypeScript, Tailwind CSS | Server-side rendered dashboard, client-side interactivity | 3000 |
| **API** | `api` | FastAPI, async SQLAlchemy, Pydantic v2 | REST API, auth middleware, data access layer | 8000 |
| **Worker** | `worker` | Python RQ | Background feed ingestion, AI summarization | — |
| **Scheduler** | `scheduler` | APScheduler | Cron-driven job enqueueing | — |
| **PostgreSQL** | `postgres` | PostgreSQL 16 + TimescaleDB | Primary data store (time-series hypertables) | 5432 |
| **Redis** | `redis` | Redis 7 Alpine | Job queue (RQ) + API response cache | 6379 |
| **OpenSearch** | `opensearch` | OpenSearch 2.13 | Full-text IOC search + analytics | 9200 |

### Service Dependencies

```
UI ──► API ──► PostgreSQL (health check: service_healthy)
              ──► Redis (health check: service_healthy)
              ──► OpenSearch (health check: service_healthy)

Worker ──► PostgreSQL + Redis + OpenSearch

Scheduler ──► Redis (enqueues jobs only)
```

---

## Data Architecture

### Database Schema (PostgreSQL + TimescaleDB)

```
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
|-------|------|---------|
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
|-------|-------|------|---------|
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

```
Route Handler (thin) ──► Service Layer (business logic) ──► Data Layer (ORM / cache)
         │                        │                              │
         ▼                        ▼                              ▼
   Pydantic schema          Scoring engine              SQLAlchemy async
   validation               AI summarization            Redis cache
   Auth middleware           Feed normalization          OpenSearch client
```

### Module Breakdown

| Layer | Path | Responsibility |
|-------|------|----------------|
| **Core** | `api/app/core/` | Config, database pool, Redis client, OpenSearch client, structured logging |
| **Middleware** | `api/app/middleware/` | Auth (JWT session + Cloudflare JWT verify), audit logging |
| **Models** | `api/app/models/` | SQLAlchemy ORM model definitions |
| **Schemas** | `api/app/schemas/` | Pydantic v2 request/response schemas |
| **Routes** | `api/app/routes/` | Thin route handlers — validate, delegate to service, return response |
| **Services** | `api/app/services/` | All business logic: auth, database access, scoring, search, AI, export, MITRE ATT&CK, graph, notifications, reports, domain config, feed connectors |
| **Feeds** | `api/app/services/feeds/` | Plugin-based feed connectors (inherit from `BaseFeedConnector`) |

### Endpoint Map (46 endpoints across 10 route files)

| Method | Endpoint | Auth | Handler | Service |
|--------|----------|------|---------|---------|
| `GET` | `/api/v1/health` | None | `routes/health.py` | — |
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
| `POST` | `/api/v1/search` | Viewer | `routes/search.py` | `services/search.py` |
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
| `GET` | `/api/v1/reports/{id}/export` | Viewer | `routes/reports.py` | `services/reports.py` | `?format=markdown\|pdf\|stix\|html\|csv` |

---

## Frontend Architecture

### Stack

| Concern | Technology |
|---------|-----------|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript (strict) |
| Styling | Tailwind CSS 3.4 + CSS variables |
| UI primitives | shadcn/ui (Card, Badge, Button, Input, Tabs) |
| Charts | Recharts 2.12 (DonutChart, TrendLineChart, HorizontalBarChart) |
| State | Zustand 4.5 (single store, no prop drilling) |
| Icons | Lucide React |
| API client | Custom fetch wrapper with error handling |

### Page Layout

```
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

```
app/layout.tsx (root HTML, dark class)
├── login/page.tsx (IntelWatch branded login — SSO or dev bypass)
└── (app)/layout.tsx (AuthGuard + Sidebar + Header + NotificationBell + ErrorBoundary + main area)
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
    │   └── IntelCard (with DataTooltip on risk score)
    ├── investigate/page.tsx (GraphExplorer)
    ├── techniques/page.tsx (ATTACKMatrix)
    ├── search/page.tsx
    ├── iocs/page.tsx
    ├── analytics/page.tsx
    ├── reports/page.tsx → reports/new/page.tsx, reports/[id]/page.tsx
    ├── geo/page.tsx
    ├── feeds/page.tsx
    └── settings/page.tsx

Shared Components (14 root + 4 charts + 6 ui primitives):
├── AuthGuard (route protection wrapper)
├── ErrorBoundary / WidgetErrorBoundary (page + widget error recovery)
├── EmptyState (no-data guidance per Instruction.md)
├── Loading (skeleton-based page loading, no spinners)
├── NotificationBell (header bell + dropdown via React Portal)
├── Sidebar (4-section navigation)
├── StatCard, IntelCard, FeedStatusPanel, RankedDataList, ThreatLevelBar
├── GraphExplorer (SVG force-directed graph)
├── ATTACKMatrix (MITRE ATT&CK heatmap grid)
├── Pagination (page/pages/onPageChange)
├── Tooltip / DataTooltip (Radix UI — score/status metadata)
├── charts/ — DonutChart, HorizontalBarChart, TrendLineChart
└── ui/ — badge, button, card, input, tabs, tooltip (shadcn/ui primitives)
```

---

## Worker Architecture

### Job Processing

```
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

### Schedule (14 jobs)

| Job | Interval | Queue | Priority |
|-----|----------|-------|----------|
| CISA KEV | 5 min | high | Critical (exploited vulns) |
| URLhaus | 5 min | high | High (active malicious URLs) |
| NVD | 15 min | default | Medium (new CVEs) |
| AbuseIPDB | 15 min | default | Medium (IP reputation) |
| VirusTotal | 15 min | default | Medium (malware hashes, URLs) |
| OTX | 30 min | low | Medium (campaign intel) |
| Shodan | 30 min | low | Medium (exposed services) |
| Dashboard Refresh | 2 min | low | Low (refresh materialized views) |
| AI Summaries | 5 min | low | Low (enrichment pass) |
| ATT&CK Sync | 24 hrs | low | Low (refresh STIX data) |
| ATT&CK Mapping | 10 min | low | Low (auto-map intel→techniques) |
| Relationship Builder | 15 min | low | Low (discover shared IOC/CVE/technique edges) |
| IOC Extraction | 10 min | low | Low (extract IOCs from intel items) |
| Notification Eval | 5 min | low | Low (evaluate rules, create in-app alerts) |

---

## Security Architecture

### Authentication Flow

```
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
|------|------------|
| `viewer` | Read dashboard, intel, search, techniques, graph, reports, notifications, feed status, export intel |
| `analyst` | Viewer + create/update/delete reports, manage report items, generate AI summaries |
| `admin` | Analyst + trigger feeds, manage users, setup config/status |

### Security Layers

| Layer | Implementation |
|-------|---------------|
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

```
VPS (2 vCPU, 4 GB RAM minimum)
    │
    ├── Docker Compose (7 services)
    ├── Cloudflare Tunnel (Argo) → intelwatch.trendsmap.in
    ├── Let's Encrypt via Cloudflare (automatic HTTPS)
    └── GitHub Actions CI/CD (build → push → SSH deploy)
```

### CI/CD Pipeline

```
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

> Last updated: **2026-02-28** (Phase 1 complete — all 5 sub-phases)

### Lines of Code by Category

| Category | Lines | Files | Description |
|----------|------:|------:|-------------|
| Python (API + Worker) | 6,831 | 50 | FastAPI routes, services, models, schemas, feeds, worker tasks |
| TypeScript/TSX (UI) | 8,589 | 49 | Next.js pages, components, store, types, API client |
| Markdown (Docs) | 2,648 | 7 | Architecture, roadmap, instructions, integration, technology |
| Config (JSON/YAML/CSS/TOML) | 517 | 8 | package.json, tailwind, tsconfig, docker-compose, OpenSearch mapping |
| SQL (Schema + Migrations) | 468 | 3 | PostgreSQL + TimescaleDB DDL, indexes, materialized views |
| Docker | 262 | 5 | Multi-stage Dockerfiles (API, UI, Worker), compose files |
| **TOTAL** | **~19,315** | **~122** | |

### Documentation Breakdown

| File | Lines | Content |
|------|------:|---------|
| docs/ROADMAP.md | 784 | 7-phase feature roadmap with implementation details |
| docs/Instruction.md | 514 | Development rules, UI guidelines, mandatory checklists |
| docs/ARCHITECTURE.md | ~540 | System architecture, DB schema (41 indexes), API endpoints (46) |
| docs/INTEGRATION.md | 382 | Feed connector specs, API integration patterns |
| docs/TECHNOLOGY.md | 218 | Tech stack decisions and rationale |
| README.md | 157 | Project overview, quick start, deployment |
| docs/WORKFLOW.md | 134 | Git workflow, CI/CD, deployment procedures |

### Growth Milestones

| Date | Milestone | Total LOC |
|------|-----------|----------:|
| 2026-02-23 | Initial platform (7 feeds, dashboard, search) | ~8,500 |
| 2026-02-26 | Phase 1.1 — MITRE ATT&CK (691 techniques, matrix UI) | ~12,000 |
| 2026-02-27 | Phase 1.2 — Relationship Graph (3,875 edges, graph explorer) | ~16,400 |
| 2026-02-28 | Phase 1.3 — Notifications & Alerting (rules, bell, 12 endpoints) | ~17,500 |
| 2026-02-28 | Phase 1.4 — Report Generation (templates, AI summary, export) | ~18,800 |
| 2026-02-28 | Phase 1.5 — VirusTotal & Shodan Connectors | ~19,315 |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-02-28 | Multi-format export: PDF (reportlab + TLP watermark), STIX 2.1 Bundle, HTML (dark-theme), CSV; UI export dropdown with 5 format options; updated codebase metrics |
| 2026-02-28 | Phase 1.4 Report Generation: reports + report_items tables, 11 report endpoints, 3 UI pages, templates, AI summary, multi-format export (PDF, STIX 2.1, HTML, CSV, Markdown) |
| 2026-02-28 | Phase 1.3 Notifications & Alerting: notification_rules + notifications tables, 12 notification endpoints, NotificationBell component, worker eval task |
| 2026-02-28 | Post-audit fixes: OpenSearch dedup (834K→3,944), ATT&CK keyword precision, skeleton loaders, ErrorBoundary, Tooltip system |
| 2026-02-28 | Phase 1.2 Relationship Graph; added Codebase Metrics section |
| 2026-02-24 | Production domain set to intelwatch.trendsmap.in; simplified login docs |
| 2026-02-24 | Renamed to IntelWatch; added VirusTotal & Shodan API key support; login testing verified |
| 2026-02-23 | Renamed to IntelWatch TI Platform; added auth architecture (JWT sessions, login flow, auth guard) |
| 2026-02-23 | Initial architecture document extracted from README |
