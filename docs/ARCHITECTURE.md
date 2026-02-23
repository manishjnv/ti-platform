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

---

## System Overview

The Threat Intelligence Platform is a **self-hosted, containerized** system that aggregates, normalizes, scores, and visualizes threat intelligence from multiple open-source feeds. It is designed as a modular monolith — each concern is cleanly separated into its own layer and can be independently scaled.

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
| **Middleware** | `api/app/middleware/` | Auth (Cloudflare JWT verify), audit logging |
| **Models** | `api/app/models/` | SQLAlchemy ORM model definitions |
| **Schemas** | `api/app/schemas/` | Pydantic v2 request/response schemas |
| **Routes** | `api/app/routes/` | Thin route handlers — validate, delegate to service, return response |
| **Services** | `api/app/services/` | All business logic: scoring, search, AI, export, feed connectors |
| **Feeds** | `api/app/services/feeds/` | Plugin-based feed connectors (inherit from `BaseFeedConnector`) |

### Endpoint Map

| Method | Endpoint | Auth | Handler | Service |
|--------|----------|------|---------|---------|
| `GET` | `/api/v1/health` | None | `routes/health.py` | — |
| `GET` | `/api/v1/dashboard` | Viewer | `routes/dashboard.py` | `services/database.py` |
| `GET` | `/api/v1/intel` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/intel/{id}` | Viewer | `routes/intel.py` | `services/database.py` |
| `GET` | `/api/v1/search` | Viewer | `routes/search.py` | `services/search.py` |
| `POST` | `/api/v1/admin/ingest` | Admin | `routes/admin.py` | `services/feeds/*` |
| `GET` | `/api/v1/admin/feeds` | Admin | `routes/admin.py` | `services/database.py` |

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
│  │  IOC Search    │    │                         │
│  │  IOC Database  │    │   (cards, charts,       │
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
└── (app)/layout.tsx (Sidebar + Header + main area)
    ├── dashboard/page.tsx
    │   ├── StatCard ×4
    │   ├── ThreatLevelBar
    │   ├── DonutChart ×2
    │   ├── HorizontalBarChart
    │   ├── RankedDataList ×2
    │   ├── FeedStatusPanel
    │   └── Data Table
    ├── threats/page.tsx
    ├── intel/page.tsx → intel/[id]/page.tsx
    ├── search/page.tsx
    ├── iocs/page.tsx
    ├── analytics/page.tsx
    ├── geo/page.tsx
    ├── feeds/page.tsx
    └── settings/page.tsx
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

---

## Security Architecture

### Authentication Flow

```
Browser ──► Cloudflare Access (Zero Trust) ──► SSO Provider (Google)
                    │
                    ▼
            JWT in Cf-Access-Jwt-Assertion header
                    │
                    ▼
            API middleware verifies JWT + extracts user
                    │
                    ▼
            RBAC check (admin / analyst / viewer)
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
| Auth | Cloudflare Zero Trust SSO + JWT verification |
| RBAC | Role-based decorators on route handlers |
| Input | Pydantic v2 strict validation on all endpoints |
| Queries | SQLAlchemy ORM — parameterized only |
| Rate limiting | Configurable per-endpoint rate limits |
| Audit | All mutations and auth events logged to `audit_log` hypertable |
| Secrets | Environment variables only — never in code |

---

## Deployment Architecture

### Production

```
VPS (2 vCPU, 4 GB RAM minimum)
    │
    ├── Docker Compose (7 services)
    ├── Cloudflare Tunnel (Argo) → ti.yourdomain.com
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

## Revision History

| Date | Change |
|------|--------|
| 2026-02-23 | Initial architecture document extracted from README |
