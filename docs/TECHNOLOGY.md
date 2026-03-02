# Technology Stack

> **Living document** — updated when new technologies are added to the platform.

---

## Table of Contents

- [Stack Overview](#stack-overview)
- [Backend](#backend)
- [Frontend](#frontend)
- [Data Stores](#data-stores)
- [Infrastructure](#infrastructure)
- [Development Tools](#development-tools)
- [Key Libraries & Rationale](#key-libraries--rationale)
- [Version Matrix](#version-matrix)

---

## Stack Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION                                │
│  Next.js 14 · TypeScript · Tailwind CSS · Recharts · Zustand       │
├─────────────────────────────────────────────────────────────────────┤
│                           API LAYER                                 │
│  FastAPI · Pydantic v2 · async SQLAlchemy · aiohttp                │
├─────────────────────────────────────────────────────────────────────┤
│                        BUSINESS LOGIC                               │
│  Feed Connectors · Risk Scoring · AI Summarization · Search        │
├─────────────────────────────────────────────────────────────────────┤
│                         DATA LAYER                                  │
│  PostgreSQL 16 + TimescaleDB · OpenSearch 2.13 · Redis 7           │
├─────────────────────────────────────────────────────────────────────┤
│                       INFRASTRUCTURE                                │
│  Docker · Docker Compose · Cloudflare Tunnel · GitHub Actions      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Backend

### FastAPI (API Server)

| Attribute | Detail |
|-----------|--------|
| Framework | FastAPI |
| Python | 3.12 |
| ASGI server | Uvicorn |
| Why FastAPI | Async-native, auto OpenAPI docs, Pydantic integration, high performance |

**Key features used:**
- Async request handlers (`async def`)
- Dependency injection (auth, DB sessions)
- Middleware stack (CORS, rate limiting, audit logging)
- Background tasks
- Auto-generated OpenAPI/Swagger docs

### Pydantic v2 (Validation)

| Attribute | Detail |
|-----------|--------|
| Version | v2 (Rust-based core) |
| Usage | Request/response schemas, config parsing, data validation |
| Why | 5-50x faster than v1, strict mode, JSON Schema generation |

### SQLAlchemy (ORM)

| Attribute | Detail |
|-----------|--------|
| Version | 2.x (async) |
| Driver | `asyncpg` (async PostgreSQL) |
| Usage | All database queries, model definitions, migrations |
| Why | Async support, mature ORM, parameterized queries by default |

### Python RQ (Job Queue)

| Attribute | Detail |
|-----------|--------|
| Backend | Redis |
| Usage | Background feed ingestion, AI summarization jobs |
| Why | Simple, Redis-backed, Python-native, no broker overhead |

### APScheduler (Scheduler)

| Attribute | Detail |
|-----------|--------|
| Usage | Cron-style job scheduling for feed sync intervals |
| Why | Lightweight, no external dependencies beyond Redis |

---

## Frontend

### Next.js 14 (Framework)

| Attribute | Detail |
|-----------|--------|
| Version | 14.2 |
| Router | App Router |
| Rendering | SSR + client-side hydration |
| Why | File-based routing, code splitting, SSR for SEO/performance, React Server Components |

### TypeScript (Language)

| Attribute | Detail |
|-----------|--------|
| Strictness | Strict mode enabled |
| Usage | All frontend code — components, hooks, store, API client, types |
| Why | Type safety, refactoring confidence, IDE support |

### Tailwind CSS (Styling)

| Attribute | Detail |
|-----------|--------|
| Version | 3.4 |
| Config | Custom dark theme via CSS variables |
| Extensions | `sidebar`, `chart-1` through `chart-5` custom colors |
| Why | Utility-first, no CSS files to maintain, design token consistency |

### shadcn/ui (UI Primitives)

| Attribute | Detail |
|-----------|--------|
| Components | Card, Badge, Button, Input, Tabs |
| Why | Copy-paste components (not a dependency), Radix UI accessibility, Tailwind-native |

### Recharts (Data Visualization)

| Attribute | Detail |
|-----------|--------|
| Version | 2.12 |
| Chart types | PieChart (donut), AreaChart (trends), BarChart (horizontal bars) |
| Custom components | DonutChart, TrendLineChart, HorizontalBarChart |
| Why | React-native, composable, responsive, good TypeScript support |

### Zustand (State Management)

| Attribute | Detail |
|-----------|--------|
| Version | 4.5 |
| Pattern | Single store, action-based mutations |
| Why | Minimal boilerplate, no context providers, hook-based, no prop drilling |

### Lucide React (Icons)

| Attribute | Detail |
|-----------|--------|
| Usage | All UI icons (sidebar nav, stat cards, badges, actions) |
| Why | Tree-shakable, consistent design, 1000+ icons |

---

## Data Stores

### PostgreSQL + TimescaleDB (Primary Database)

| Attribute | Detail |
|-----------|--------|
| PostgreSQL | Version 16 |
| TimescaleDB | Latest (extension) |
| Image | `timescale/timescaledb:latest-pg16` |
| Port | 5432 |
| Why PostgreSQL | ACID, JSONB, array types, GIN indexes, trigram search, mature ecosystem |
| Why TimescaleDB | Automatic time-partitioning (hypertables), 10-100x faster time-range queries, compression |

**Features used:**
- Hypertables: `intel_items` (partitioned by `ingested_at`), `audit_log` (partitioned by `created_at`)
- GIN indexes: tags, CVE arrays, geo arrays, trigram fuzzy search
- Materialized views: `mv_severity_distribution`, `mv_top_risks`
- Extensions: `uuid-ossp`, `timescaledb`, `pg_trgm`
- Enums: `severity_level`, `feed_type`, `asset_type`, `user_role`, `sync_status`, `tlp_level`

### OpenSearch (Search Engine)

| Attribute | Detail |
|-----------|--------|
| Version | 2.13.0 |
| Port | 9200 |
| Mode | Single-node (dev/small prod) |
| Usage | Full-text IOC search, faceted queries, analytics aggregations |
| Why | Elasticsearch-compatible (Apache 2.0 license), full-text search, aggregation framework |

### Redis (Cache + Queue)

| Attribute | Detail |
|-----------|--------|
| Version | 7 Alpine |
| Port | 6379 |
| Usage | RQ job queue + API response cache (TTL-based) |
| Why | In-memory speed, pub/sub capability, RQ backend, simple caching |

---

## Infrastructure

### Docker

| Attribute | Detail |
|-----------|--------|
| Compose | v2 (Docker Compose plugin) |
| Services | 7 containers |
| Volumes | `pg_data`, `redis_data`, `os_data` (persistent) |
| Networking | Default bridge network, inter-service DNS |
| Health checks | PostgreSQL, Redis, OpenSearch (all with retries) |

### Cloudflare Tunnel (Argo)

| Attribute | Detail |
|-----------|--------|
| Purpose | Expose services without opening firewall ports |
| Auth | Zero Trust SSO (Google, GitHub, etc.) |
| TLS | Automatic via Cloudflare |
| Config | `cloudflare/tunnel-config.yml` |

### GitHub Actions (CI/CD)

| Attribute | Detail |
|-----------|--------|
| Trigger | Push to `main` |
| Steps | Lint → Build → Push to GHCR → SSH deploy |
| Config | `.github/workflows/ci.yml` |

---

## AI Enrichment (Multi-Provider Fallback)

The platform uses OpenAI-compatible APIs for threat intelligence summarisation, news enrichment, and report generation. A **multi-provider fallback chain** ensures resilience against per-model rate limits.

### Provider Chain (priority order)

| # | Provider | Model | Free Tier Limit | Purpose |
|---|----------|-------|----------------|---------|
| 1 | **Groq** | `llama-3.3-70b-versatile` | ~100K tokens/day | Primary — fastest inference, best quality |
| 2 | **Groq** | `llama-3.1-8b-instant` | ~100K tokens/day (separate bucket) | Lightweight fallback, same provider |
| 3 | **Cerebras** | `qwen-3-235b-a22b-instruct-2507` | Free tier | 235B model, different provider |
| 4 | **Groq** | `qwen/qwen3-32b` | ~100K tokens/day (separate bucket) | Qwen3 32B on Groq |
| 5 | **HuggingFace** | `Mistral-7B-Instruct-v0.3` | Free tier | External fallback |

### Failover Logic

```text
Request → Groq primary (70B)
             │
             ├─ 200 OK → return response
             │
             └─ 429/503 → Groq 8B instant
                              │
                              ├─ 200 OK → return response
                              │
                              └─ 429/503 → Cerebras Qwen3 235B
                                               │
                                               ├─ 200 OK → return response
                                               │
                                               └─ 429/503 → Groq Qwen3 32B
                                                                │
                                                                └─ 429/503 → HuggingFace Mistral
                                                                                 │
                                                                                 └─ 429/503 → None (skip item)
```

### Configuration

| Env Variable | Service | Description |
|-------------|---------|-------------|
| `AI_API_URL` | api, worker | Primary endpoint (Groq) |
| `AI_API_KEY` | api, worker | Primary Groq API key |
| `AI_MODEL` | api, worker | Primary model name |
| `CEREBRAS_API_KEY` | api, worker | Cerebras free tier key |
| `HF_API_KEY` | api, worker | HuggingFace Inference API key |
| `AI_TIMEOUT` | api, worker | Request timeout (seconds, default 30) |
| `AI_ENABLED` | api, worker | Master kill-switch for all AI features |

### Key Files

| File | Purpose |
|------|---------|
| `api/app/services/ai.py` | Fallback chain, `_call_with_fallback()`, `generate_summary()`, `chat_completion()` |
| `api/app/core/config.py` | All AI env settings (`ai_*`, `cerebras_api_key`, `hf_api_key`) |
| `api/app/services/news.py` | News-specific AI prompt with banned generic phrases |
| `worker/tasks.py` | `enrich_news_batch()` — calls `chat_completion()` via fallback chain |

---

## Development Tools

| Tool | Purpose |
|------|---------|
| **ruff** | Python linter + formatter (replaces flake8, isort, black) |
| **tsc** | TypeScript type checking |
| **Docker Compose dev overlay** | Hot reload for API, worker, UI |
| **Uvicorn --reload** | API live reload in development |
| **Next.js HMR** | Frontend hot module replacement |

---

## Key Libraries & Rationale

| Library | Layer | Why Chosen Over Alternatives |
|---------|-------|------------------------------|
| **python-jose** | Auth | JWT token creation/verification (HS256, RS256) |
| **FastAPI** | Backend | Async-native, auto docs (vs. Flask/Django — sync, heavier) |
| **asyncpg** | DB driver | Fastest Python PostgreSQL driver (vs. psycopg2 — sync) |
| **Pydantic v2** | Validation | Rust core, 5-50x faster (vs. marshmallow, attrs) |
| **Next.js 14** | Frontend | SSR + App Router + file routing (vs. CRA — no SSR) |
| **Tailwind CSS** | Styling | Utility-first, design tokens (vs. CSS modules — more verbose) |
| **Zustand** | State | Minimal, hook-based (vs. Redux — too much boilerplate) |
| **Recharts** | Charts | React-native, composable (vs. D3 — lower-level, more work) |
| **TimescaleDB** | Time-series | Native PG extension (vs. InfluxDB — separate system) |
| **OpenSearch** | Search | Apache 2.0, ES-compatible (vs. Elasticsearch — license issues) |
| **Redis + RQ** | Queue | Simple Python jobs (vs. Celery — heavier for our needs) |
| **Docker Compose** | Infra | Single-host simplicity (vs. K8s — overkill for Phase 1) |

---

## Version Matrix

| Component | Version | Update Policy |
|-----------|---------|---------------|
| Python | 3.12 | LTS cycle |
| Node.js | 20 (LTS) | Even-numbered LTS |
| PostgreSQL | 16 | Major every ~1 year |
| TimescaleDB | Latest | Follows PG releases |
| OpenSearch | 2.13 | Quarterly releases |
| Redis | 7 | Stable branch |
| FastAPI | Latest | Semver, frequent |
| Next.js | 14.2 | Major yearly |
| Tailwind CSS | 3.4 | Semver |
| Docker Compose | v2 | Bundled with Docker |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-02-27 | Added AI Enrichment section — multi-provider fallback chain (Groq, Cerebras, HuggingFace) |
| 2026-02-24 | Production domain: intelwatch.trendsmap.in; CORS updated |
| 2026-02-24 | Added VirusTotal & Shodan API key configuration |
| 2026-02-23 | Added python-jose for JWT auth; updated for IntelWatch branding |
| 2026-02-23 | Initial technology stack document created |
