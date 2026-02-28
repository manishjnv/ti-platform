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

| Service | Container | Technology | Responsibility | Port |
|---------|-----------|-----------|----------------|------|
| **UI** | `ti-platform-ui` | Next.js 14, TypeScript, Tailwind CSS | Server-side rendered dashboard, client-side interactivity | 3000 |
| **API** | `ti-platform-api` | FastAPI, async SQLAlchemy, Pydantic v2 | REST API, auth middleware, data access layer | 8000 |
| **Worker** | `ti-platform-worker` | Python RQ | Background feed ingestion, AI summarization | — |
| **Scheduler** | `ti-platform-scheduler` | APScheduler | Cron-driven job enqueueing | — |
| **PostgreSQL** | `ti-platform-postgres` | PostgreSQL 16 + TimescaleDB | Primary data store (time-series hypertables) | 5432 |
| **Redis** | `ti-platform-redis` | Redis 7 Alpine | Job queue (RQ) + API response cache | 6379 |
| **OpenSearch** | `ti-platform-opensearch` | OpenSearch 2.13 | Full-text IOC search + analytics | 9200 |

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
┌─────────────────────────────────────────────────────────────────────┐
│                          TimescaleDB                                │
│                                                                     │
│  ┌─────────────────┐          ┌──────────────┐                      │
│  │  intel_items     │──────1:N──►│  iocs         │                   │
│  │  (hypertable)    │          │              │                      │
│  │  partitioned by  │          └──────────────┘                      │
│  │  ingested_at     │                  ▲                             │
│  └────────┬─────────┘                  │                             │
│           │                ┌───────────┴──────────┐                  │
│           │                │  intel_ioc_links     │                  │
│           └────────────────►│  (junction table)    │                  │
│                            └──────────────────────┘                  │
│                                                                     │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐   │
│  │  users        │  │  feed_sync_state │  │  audit_log           │   │
│  │              │  │                  │  │  (hypertable)        │   │
│  └──────────────┘  └──────────────────┘  └──────────────────────┘   │
│                                                                     │
│  Materialized Views:                                                │
│  ├── mv_severity_distribution (30-day rollup)                       │
│  └── mv_top_risks (risk_score ≥ 70, top 100)                       │
│                                                                     │
│  ┌──────────────────┐                                               │
│  │  scoring_config   │  (configurable risk scoring weights)         │
│  └──────────────────┘                                               │
│                                                                     │
│  ┌────────────────────┐   ┌──────────────────────┐                  │
│  │  attack_techniques  │◄──│  intel_attack_links   │                  │
│  │  (691 MITRE ATT&CK) │   │  (junction table)    │                  │
│  └────────────────────┘   └──────────────────────┘                  │
│                                                                     │
│  ┌────────────────────┐                                             │
│  │   relationships     │  (1,181 auto-discovered graph edges)       │
│  │  (source↔target     │                                            │
│  │   + type + conf)    │                                            │
│  └────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────┘
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
| `mv_severity_distribution` | Materialized view | Pre-computed 30-day severity stats |
| `mv_top_risks` | Materialized view | Pre-computed top-100 high-risk items |

### Indexing Strategy

| Index | Type | Purpose |
|-------|------|---------|
| `idx_intel_severity` | B-tree | Fast severity + time filtering |
| `idx_intel_risk` | B-tree | Fast risk-score ordering |
| `idx_intel_source` | B-tree | Filter by source name |
| `idx_intel_feed_type` | B-tree | Filter by feed type |
| `idx_intel_kev` | Partial B-tree | Fast KEV lookups (WHERE is_kev = TRUE) |
| `idx_intel_tags` | GIN | Array containment queries on tags |
| `idx_intel_cve` | GIN | Array containment queries on CVE IDs |
| `idx_intel_geo` | GIN | Array containment queries on geo |
| `idx_intel_title_trgm` | GIN (trigram) | Fuzzy text search on titles |
| `idx_iocs_value_trgm` | GIN (trigram) | Fuzzy IOC value search |
| `idx_attack_tactic` | B-tree | Filter techniques by tactic phase |
| `idx_attack_parent` | B-tree | Sub-technique→parent lookups |
| `idx_attack_name_trgm` | GIN (trigram) | Fuzzy technique name search |
| `idx_rel_source` | B-tree | Find edges by source entity |
| `idx_rel_target` | B-tree | Find edges by target entity |
| `idx_rel_type` | B-tree | Filter by relationship type |
| `idx_rel_confidence` | B-tree (desc) | Rank by confidence score |
| `idx_rel_unique_edge` | Unique B-tree | Prevent duplicate edges |
| `idx_ial_technique` | B-tree | Fast technique→intel lookups |

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
| **Services** | `api/app/services/` | All business logic: auth, scoring, search, AI, export, MITRE ATT&CK, domain config, feed connectors |
| **Feeds** | `api/app/services/feeds/` | Plugin-based feed connectors (inherit from `BaseFeedConnector`) |

### Endpoint Map

| Method | Endpoint | Auth | Handler | Service |
|--------|----------|------|---------|---------|
| `GET` | `/api/v1/health` | None | `routes/health.py` | — |
| `GET` | `/api/v1/auth/config` | None | `routes/auth.py` | `services/auth.py` |
| `POST` | `/api/v1/auth/login` | None | `routes/auth.py` | `services/auth.py` |
| `POST` | `/api/v1/auth/logout` | Cookie | `routes/auth.py` | `services/auth.py` |
| `GET` | `/api/v1/auth/session` | Cookie | `routes/auth.py` | `services/auth.py` |
| `GET` | `/api/v1/dashboard` | Viewer | `routes/dashboard.py` | `services/database.py` |
| `GET` | `/api/v1/intel` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/intel/{id}` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/search` | Viewer | `routes/search.py` | `services/search.py` |
| `POST` | `/api/v1/admin/ingest` | Admin | `routes/admin.py` | `services/feeds/*` |
| `GET` | `/api/v1/admin/feeds` | Admin | `routes/admin.py` | `services/database.py` |
| `GET` | `/api/v1/setup/config` | Admin | `routes/admin.py` | `services/domain.py` |
| `GET` | `/api/v1/setup/status` | Admin | `routes/admin.py` | `services/domain.py` |
| `GET` | `/api/v1/techniques` | Viewer | `routes/techniques.py` | `services/mitre.py` |
| `GET` | `/api/v1/techniques/matrix` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/techniques/{id}` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/techniques/intel/{id}/techniques` | Viewer | `routes/techniques.py` | — |
| `GET` | `/api/v1/graph/explore` | Viewer | `routes/graph.py` | `services/graph.py` |
| `GET` | `/api/v1/graph/related/{id}` | Viewer | `routes/graph.py` | `services/graph.py` |
| `GET` | `/api/v1/graph/stats` | Viewer | `routes/graph.py` | `services/graph.py` |

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
│  │  Investigate   │    │                         │
│  │  ATT&CK Map   │    │   (cards, charts,       │
│  │  IOC Search    │    │    tables, filters)     │
│  │  IOC Database  │    │                         │
│  │ Analytics      │    │    tables, filters)     │
│  │  Analytics     │    │                         │
│  │  Geo View      │    │                         │
│  │ System         │    │                         │
│  │  Feed Status   │    │                         │
│  │  Settings      │    │                         │
│  └────────────────┘    │                         │
└──────────────────────────────────────────────────┘
```

### Component Hierarchy

```
app/layout.tsx (root HTML, dark class)
├── login/page.tsx (IntelWatch branded login — SSO or dev bypass)
└── (app)/layout.tsx (AuthGuard + Sidebar + Header + ErrorBoundary + main area)
    ├── dashboard/page.tsx
    │   ├── StatCard ×4 (with optional tooltip)
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
    ├── search/page.tsx
    ├── iocs/page.tsx
    ├── analytics/page.tsx
    ├── geo/page.tsx
    ├── feeds/page.tsx
    └── settings/page.tsx

Shared:
├── ErrorBoundary / WidgetErrorBoundary (page + widget error recovery)
├── Loading (skeleton-based page loading, no spinners)
├── EmptyState (no-data guidance per Instruction.md)
├── Tooltip / DataTooltip (Radix UI — score/status metadata)
└── Skeleton / IntelCardSkeleton (loading placeholders)
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

### Schedule

| Feed | Interval | Priority |
|------|----------|----------|
| CISA KEV | 5 min | Critical (exploited vulns) |
| URLhaus | 5 min | High (active malicious URLs) |
| NVD | 15 min | Medium (new CVEs) |
| AbuseIPDB | 15 min | Medium (IP reputation) |
| OTX | 30 min | Medium (campaign intel) |
| AI Summaries | 5 min | Low (enrichment pass) |
| ATT&CK Sync | 6 hrs | Low (refresh STIX data) |
| ATT&CK Mapping | 10 min | Low (auto-map intel→techniques) |
| Relationship Builder | 15 min | Low (discover shared IOC/CVE/technique edges) |

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
| `viewer` | Read dashboard, intel, search |
| `analyst` | Viewer + export, advanced search |
| `admin` | Analyst + trigger ingestion, manage feeds, settings |

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

> Last updated: **2026-02-28** (Phase 1.2 complete)

### Lines of Code by Category

| Category | Lines | Files | Description |
|----------|------:|------:|-------------|
| Python (API + Worker) | 6,116 | 47 | FastAPI routes, services, models, schemas, feeds, worker tasks |
| TypeScript/TSX (UI) | 5,943 | 42 | Next.js pages, components, store, types, API client |
| Markdown (Docs) | 3,116 | 7 | Architecture, roadmap, instructions, integration, technology |
| Config (JSON/YAML/CSS) | 604 | 10 | package.json, tailwind, tsconfig, docker-compose, OpenSearch mapping |
| SQL (Schema) | 307 | 1 | PostgreSQL + TimescaleDB DDL, indexes, materialized views |
| Docker | 298 | 5 | Multi-stage Dockerfiles (API, UI, Worker), compose files |
| **TOTAL** | **16,384** | **112** | |

### Documentation Breakdown

| File | Lines | Content |
|------|------:|---------|
| docs/ROADMAP.md | 854 | 7-phase feature roadmap with implementation details |
| docs/Instruction.md | 618 | Development rules, UI guidelines, mandatory checklists |
| docs/INTEGRATION.md | 504 | Feed connector specs, API integration patterns |
| docs/ARCHITECTURE.md | 473 | System architecture, DB schema, API endpoints |
| docs/TECHNOLOGY.md | 283 | Tech stack decisions and rationale |
| README.md | 207 | Project overview, quick start, deployment |
| docs/WORKFLOW.md | 177 | Git workflow, CI/CD, deployment procedures |

### Growth Milestones

| Date | Milestone | Total LOC |
|------|-----------|----------:|
| 2026-02-23 | Initial platform (7 feeds, dashboard, search) | ~8,500 |
| 2026-02-26 | Phase 1.1 — MITRE ATT&CK (691 techniques, matrix UI) | ~12,000 |
| 2026-02-28 | Phase 1.2 — Relationship Graph (1,181 edges, graph explorer) | 16,384 |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-02-28 | Post-audit fixes: OpenSearch dedup (834K→3,944), ATT&CK keyword precision, skeleton loaders, ErrorBoundary, Tooltip system |
| 2026-02-28 | Phase 1.2 Relationship Graph; added Codebase Metrics section (16,384 LOC / 112 files) |
| 2026-02-24 | Production domain set to intelwatch.trendsmap.in; simplified login docs |
| 2026-02-24 | Renamed to IntelWatch; added VirusTotal & Shodan API key support; login testing verified |
| 2026-02-23 | Renamed to IntelWatch TI Platform; added auth architecture (JWT sessions, login flow, auth guard) |
| 2026-02-23 | Initial architecture document extracted from README |
