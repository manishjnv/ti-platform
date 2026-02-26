# IntelWatch — TI Platform

> **Phase-1** — Live threat feeds, IOC search, risk scoring, analytics dashboards.

A production-grade, self-hosted threat intelligence aggregation and analysis platform built with **FastAPI**, **Next.js 14**, **PostgreSQL/TimescaleDB**, **OpenSearch**, and **Redis**.

![Stack](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![Stack](https://img.shields.io/badge/Next.js_14-000000?style=flat&logo=next.js&logoColor=white)
![Stack](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat&logo=postgresql&logoColor=white)
![Stack](https://img.shields.io/badge/TimescaleDB-FDB515?style=flat&logo=timescale&logoColor=black)
![Stack](https://img.shields.io/badge/OpenSearch-005EB8?style=flat&logo=opensearch&logoColor=white)
![Stack](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)
![Stack](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)

---

## Table of Contents

- [Project Standards (Permanent)](#-project-standards--permanent-rules)
- [Architecture](#architecture)
- [Pages & Features](#pages--features)
- [Folder Structure](#folder-structure)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Feed Connectors](#feed-connectors)
- [API Reference](#api-reference)
- [Data Flow](#data-flow)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Login & Authentication](#-login--authentication)
- [Documentation Index](#-documentation-index)

---

## 📐 Project Standards — Permanent Rules

> **This section is the SOURCE OF TRUTH for all development.**
> Every feature, refactor, and phase MUST comply with these standards.
> If a new feature conflicts with these rules — **redesign the feature, not the standards.**

### 📁 Codebase Organization (Mandatory)

- Strict **modular architecture** — clean separation of concerns.
- No monolithic files. No mixed responsibilities.
- Every module must be easy to **extend, refactor, test, and scale**.
- Business logic lives in `services/`, NOT in route handlers.
- Folder structure must be shown before implementing any new feature.

### 🔐 Security Coding Practices (Non-Negotiable)

| Area | Requirement |
|------|-------------|
| Input validation | On ALL endpoints — strict schema enforcement (Pydantic / Zod) |
| Queries | Parameterized queries / ORM only — **no raw SQL concatenation** |
| Output | Sanitized — no sensitive data leaks |
| Secrets | Environment variables only — **never hardcoded** |
| Auth | RBAC-ready, least-privilege access, Cloudflare Zero Trust SSO |
| API | Rate limiting, request size limits, secure headers, CORS policy |
| Compliance | OWASP secure coding practices |
| Logging | All security-relevant events logged (auth, access, mutations) |

### ⚡ Performance Optimization (Required by Default)

**Backend:**
- `async` everywhere possible (asyncpg, aiohttp, async Redis)
- Pagination on ALL list APIs
- Background workers (RQ) for heavy tasks
- Caching layer (Redis)
- DB indexing strategy (TimescaleDB hypertables + B-tree indexes)

**Frontend:**
- Code splitting (Next.js dynamic imports)
- Lazy loading for below-fold components
- API response caching (SWR / Zustand)
- Minimal re-renders (memoized selectors, `useMemo`)
- Optimized state management (Zustand — no prop drilling)

**Data:**
- No N+1 queries
- Bulk operations for feed ingestion
- OpenSearch for full-text / IOC search

### 📜 Enterprise-Grade Logging

Structured, centralized, SIEM-friendly logs with:

| Field | Description |
|-------|------------|
| `timestamp` | ISO-8601 |
| `module` | Source module name |
| `event_type` | `security`, `audit`, `app`, `perf` |
| `user` | Authenticated user (if available) |
| `severity` | `debug`, `info`, `warning`, `error`, `critical` |
| `request_id` | Trace ID for request correlation |

Log categories: **application**, **security**, **audit**, **performance**.

### 🎨 UI / UX Design Standards

The reference dashboard images are the **PRIMARY DESIGN BASELINE**:

- Follow their layout, spacing, component hierarchy, and visual density.
- All new UI must feel like a natural extension of the references.
- Modern dark threat-intel aesthetic (blue-tinted dark theme).
- Components must be **modular, reusable, responsive, and performant**.
- Do NOT invent random UI — every screen matches the reference design language.

### 🧠 Engineering Behavior

This is a **long-running, multi-phase production platform** — not throwaway code.

For every feature:
1. Update architecture if needed
2. Place code in the correct module
3. Wire logging
4. Update tests
5. Update README

Always: think before coding, keep files small and focused, prefer extensibility.

### 🚫 Strictly Forbidden

| ❌ Forbidden | ✅ Required Instead |
|---|---|
| Monolithic files | Small, focused modules |
| Hardcoded secrets | Environment variables |
| Business logic in routes | Logic in `services/` layer |
| Skipping validation | Pydantic / Zod schemas on every endpoint |
| Console-only logging | Structured logging to stdout (JSON) |
| Unpaginated APIs | Pagination on ALL list endpoints |
| UI ignoring reference design | Match reference dashboards |

### 📦 Output Standard for Every Implementation

1. Show updated folder structure (affected parts only)
2. Show files created / modified
3. Provide production-grade code
4. Update README section
5. Explain why the design follows project standards

---

## Architecture

```
┌──────────────┐   Cloudflare Tunnel    ┌──────────────────────────────────────────────┐
│   Browser    │ ─────────────────────► │  Docker Host                                 │
│  (SSO via    │   intelwatch.trendsmap.in    │                                              │
│  Zero Trust) │                        │  ┌──────┐  ┌──────┐  ┌────────────────┐     │
└──────────────┘                        │  │  UI  │  │  API │  │  Worker +      │     │
                                        │  │ :3000│→ │ :8000│  │  Scheduler     │     │
                                        │  └──────┘  └──┬───┘  └───────┬────────┘     │
                                        │               │              │               │
                                        │  ┌────────────┴──────────────┴────────────┐  │
                                        │  │  PostgreSQL/TimescaleDB │ Redis │ OS   │  │
                                        │  └────────────────────────────────────────┘  │
                                        └──────────────────────────────────────────────┘
```

**7 Docker services:** UI, API, Worker, Scheduler, PostgreSQL+TimescaleDB, Redis, OpenSearch

| Service | Tech | Port |
|---------|------|------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Recharts, Zustand | 3000 |
| Backend API | FastAPI, async SQLAlchemy, Pydantic v2 | 8000 |
| Database | PostgreSQL 16 + TimescaleDB | 5432 |
| Search | OpenSearch 2.x | 9200 |
| Cache/Queue | Redis 7 | 6379 |
| Worker | Python RQ (Redis Queue) | — |
| Scheduler | Python APScheduler | — |

---

## Pages & Features

| Page | Route | Description |
|------|-------|-------------|
| **Login** | `/login` | IntelWatch branded login — SSO redirect or dev bypass |
| **Dashboard** | `/dashboard` | KPI stat cards, threat level bar, severity/category donut charts, top risks table, feed status |
| **Threat Feed** | `/threats` | Severity filter pills, risk-sorted threat list, asset type breakdown |
| **Intel Items** | `/intel` | Paginated intel browser with filters, detail drill-down |
| **IOC Search** | `/search` | Full-text IOC search with type/severity/date filters |
| **IOC Database** | `/iocs` | Browse all IOCs with type filter pills, copy-to-clipboard, type distribution donut |
| **Analytics** | `/analytics` | Severity bar chart, category donut, geo/industry rankings, source reliability |
| **Geo View** | `/geo` | Geographic threat distribution, region drill-down, region-specific threat list |
| **Feed Status** | `/feeds` | Feed health monitor with status badges, error display, item counts |
| **Settings** | `/settings` | General, Security, Notifications, Appearance, Data & Storage, API Keys, Platform Setup |

**Shared components:** AuthGuard, StatCard, ThreatLevelBar, DonutChart, TrendLineChart, HorizontalBarChart, RankedDataList, FeedStatusPanel, Sidebar (4-section nav), Header bar (search, notifications, user menu).

---

## Folder Structure

```
ti-platform/
├── .github/workflows/ci.yml     # CI/CD pipeline
├── api/                          # FastAPI backend
│   ├── app/
│   │   ├── core/                 # Config, DB, Redis, OpenSearch, logging
│   │   │   ├── config.py
│   │   │   ├── database.py
│   │   │   ├── logging.py
│   │   │   ├── opensearch.py
│   │   │   └── redis.py
│   │   ├── middleware/           # Auth, audit logging
│   │   │   ├── audit.py
│   │   │   └── auth.py
│   │   ├── models/               # SQLAlchemy ORM models
│   │   │   └── models.py
│   │   ├── routes/               # API route handlers (thin — logic in services)
│   │   │   ├── admin.py
│   │   │   ├── auth.py           # Login, logout, session management
│   │   │   ├── dashboard.py
│   │   │   ├── health.py
│   │   │   ├── intel.py
│   │   │   └── search.py
│   │   ├── schemas/              # Pydantic request/response schemas
│   │   ├── services/             # Business logic layer
│   │   │   ├── ai.py
│   │   │   ├── auth.py           # JWT sessions, CF Access verification
│   │   │   ├── database.py
│   │   │   ├── domain.py         # Domain & deployment configuration
│   │   │   ├── export.py
│   │   │   ├── scoring.py
│   │   │   ├── search.py
│   │   │   └── feeds/            # Feed connector plugins
│   │   │       ├── base.py       # Abstract base connector
│   │   │       ├── abuseipdb.py
│   │   │       ├── kev.py
│   │   │       ├── nvd.py
│   │   │       ├── otx.py
│   │   │       └── urlhaus.py
│   │   └── main.py               # FastAPI app entry point
│   └── pyproject.toml
├── cloudflare/tunnel-config.yml  # Cloudflare Tunnel setup
├── db/schema.sql                 # PostgreSQL + TimescaleDB DDL
├── docker/
│   ├── Dockerfile.api
│   ├── Dockerfile.ui
│   └── Dockerfile.worker
├── opensearch/
│   └── intel-items-mapping.json  # Index mapping
├── ui/                           # Next.js 14 frontend
│   ├── src/
│   │   ├── app/
│   │   │   ├── (app)/            # Authenticated layout group
│   │   │   │   ├── layout.tsx    # Sidebar + header bar wrapper
│   │   │   │   ├── dashboard/page.tsx
│   │   │   │   ├── threats/page.tsx
│   │   │   │   ├── intel/page.tsx
│   │   │   │   ├── intel/[id]/page.tsx
│   │   │   │   ├── search/page.tsx
│   │   │   │   ├── iocs/page.tsx
│   │   │   │   ├── analytics/page.tsx
│   │   │   │   ├── geo/page.tsx
│   │   │   │   ├── feeds/page.tsx
│   │   │   │   └── settings/page.tsx
│   │   │   ├── globals.css
│   │   │   ├── layout.tsx        # Root HTML layout
│   │   │   ├── login/page.tsx    # Login page (SSO / dev bypass)
│   │   │   └── page.tsx          # Redirect → /login
│   │   ├── components/
│   │   │   ├── charts/           # Reusable chart components
│   │   │   │   ├── DonutChart.tsx
│   │   │   │   ├── HorizontalBarChart.tsx
│   │   │   │   ├── TrendLineChart.tsx
│   │   │   │   └── index.ts
│   │   │   ├── ui/               # shadcn/ui primitives
│   │   │   │   ├── badge.tsx
│   │   │   │   ├── button.tsx
│   │   │   │   ├── card.tsx
│   │   │   │   ├── input.tsx
│   │   │   │   └── tabs.tsx
│   │   │   ├── AuthGuard.tsx     # Session-gated route wrapper
│   │   │   ├── FeedStatusPanel.tsx
│   │   │   ├── IntelCard.tsx
│   │   │   ├── Loading.tsx
│   │   │   ├── Pagination.tsx
│   │   │   ├── RankedDataList.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   ├── StatCard.tsx
│   │   │   └── ThreatLevelBar.tsx
│   │   ├── hooks/                # (future — custom React hooks)
│   │   ├── lib/
│   │   │   ├── api.ts            # API client (fetch wrapper)
│   │   │   └── utils.ts          # Utility functions
│   │   ├── store/
│   │   │   └── index.ts          # Zustand global state
│   │   └── types/
│   │       └── index.ts          # TypeScript interfaces
│   ├── tailwind.config.ts
│   └── package.json
├── worker/
│   ├── tasks.py                  # RQ task definitions
│   ├── worker.py                 # RQ worker entry point
│   └── scheduler.py              # APScheduler cron jobs
├── docs/                         # Project documentation
│   ├── ARCHITECTURE.md           # System architecture deep-dive
│   ├── TECHNOLOGY.md             # Technology stack & rationale
│   └── INTEGRATION.md            # Feed & integration requirements
├── docker-compose.yml            # Production stack
├── docker-compose.dev.yml        # Dev overlay (hot reload)
├── .env.example                  # Environment template
├── .dockerignore
├── .gitignore
├── WORKFLOW.md                   # Operations & deployment guide
└── README.md                     # ← You are here
```

---

## Quick Start

### Prerequisites

- **Docker Desktop** (includes Docker Compose v2)
- *(Optional)* Python 3.12, Node.js 20 for running outside Docker

### 1. Clone & Configure

```bash
git clone https://github.com/manishjnv/ti-platform.git
cd ti-platform
cp .env.example .env
# Edit .env — set DEV_BYPASS_AUTH=true for local development
```

### 2. Start All Services

```bash
# Production mode
docker compose up -d --build

# Development mode (hot reload — recommended for local dev)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This mounts source code for live reload on API, worker, and UI.

### 3. Verify

```bash
# Health check
curl -s http://localhost:8000/api/v1/health | jq .
# Expected: {"status":"ok","postgres":true,"redis":true,"opensearch":true}

# Open UI — you'll be redirected to the login page
open http://localhost:3000
```

### 4. Test Login

See the [Login Testing Guide](#-login-testing-guide) below for detailed steps.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ENVIRONMENT` | No | `development` or `production` (default: `development`) |
| `SECRET_KEY` | **Yes** | App secret — use `openssl rand -hex 32` |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `DOMAIN` | Prod | Base domain (default: `localhost`) |
| `DOMAIN_UI` | Prod | UI URL (default: `http://localhost:3000`) |
| `DOMAIN_API` | Prod | API URL (default: `http://localhost:8000`) |
| `POSTGRES_HOST` | Yes | Database host (default: `postgres`) |
| `POSTGRES_PORT` | Yes | Database port (default: `5432`) |
| `POSTGRES_DB` | Yes | Database name (default: `ti_platform`) |
| `POSTGRES_USER` | Yes | Database user |
| `POSTGRES_PASSWORD` | **Yes** | Database password — **change in production** |
| `REDIS_URL` | Yes | Redis connection (default: `redis://redis:6379/0`) |
| `OPENSEARCH_URL` | Yes | OpenSearch endpoint |
| `DEV_BYPASS_AUTH` | No | Skip authentication in dev (default: `false`) |
| `JWT_EXPIRE_MINUTES` | No | Session duration in minutes (default: `480`) |
| `CF_ACCESS_TEAM_NAME` | Prod | Cloudflare Zero Trust team name |
| `CF_ACCESS_AUD` | Prod | Cloudflare Access audience tag |
| `CF_TUNNEL_TOKEN` | Prod | Cloudflare Tunnel token |
| `NVD_API_KEY` | No | NVD API key (higher rate limits) |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB API key (required for that feed) |
| `OTX_API_KEY` | No | AlienVault OTX API key |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal API key (free tier) |
| `SHODAN_API_KEY` | No | Shodan API key (free developer tier) |
| `AI_API_URL` | No | AI summarization endpoint |
| `AI_API_KEY` | No | AI API key |
| `AI_MODEL` | No | AI model name (default: `llama3`) |
| `NEXT_PUBLIC_API_URL` | Yes | API URL for frontend (default: `http://localhost:8000`) |

---

## Feed Connectors

| Feed | Source | Frequency | API Key |
|------|--------|-----------|---------|
| **CISA KEV** | cisa.gov Known Exploited Vulnerabilities | 5 min | No |
| **NVD** | NVD CVE 2.0 API | 15 min | Optional |
| **URLhaus** | abuse.ch malicious URL feed | 5 min | No |
| **AbuseIPDB** | AbuseIPDB blacklist API | 15 min | **Yes** |
| **OTX** | AlienVault OTX pulses | 30 min | **Yes** |
| **VirusTotal** | VirusTotal malicious files, URLs, domains | 15 min | **Yes** (free tier) |
| **Shodan** | Shodan exploits & exposed services | 30 min | **Yes** (free tier) |

All connectors inherit from `api/app/services/feeds/base.py` — adding a new feed requires implementing `fetch()` and `normalize()`.

---

## API Reference

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Service health check |
| `GET` | `/auth/config` | No | Auth method configuration (SSO vs local) |
| `POST` | `/auth/login` | No | Login — creates JWT session cookie |
| `POST` | `/auth/logout` | No | Logout — revokes session |
| `GET` | `/auth/session` | Cookie | Check session validity, return user info |
| `GET` | `/me` | Session | Current user info |
| `GET` | `/dashboard` | Viewer | Dashboard stats, severity distribution, top risks |
| `GET` | `/intel` | Viewer | Paginated intel items with filters |
| `GET` | `/intel/{id}` | Viewer | Single intel item detail |
| `GET` | `/search` | Viewer | Full-text IOC search |
| `GET` | `/feeds/status` | Viewer | Feed connector status |
| `POST` | `/feeds/{name}/trigger` | Admin | Trigger manual feed ingestion |
| `POST` | `/feeds/trigger-all` | Admin | Trigger all feed ingestions |
| `GET` | `/setup/config` | Admin | Platform domain & deployment config |
| `GET` | `/setup/status` | Admin | Platform setup checklist |

All list endpoints support `page`, `page_size`, `severity`, `feed_type`, `date_from`, `date_to` query params.

---

## Data Flow

```
1. Scheduler  ──(cron)──►  Redis Queue
2. Worker     ──(dequeue)──►  Feed Connector  ──(fetch)──►  External API
3. Worker     ──(normalize + score)──►  PostgreSQL + OpenSearch
4. API        ──(query)──►  PostgreSQL / OpenSearch / Redis cache
5. UI         ──(fetch /api/v1/*)──►  API  ──(render)──►  Browser
```

- **Scoring:** `compute_risk_score()` in `services/scoring.py` — factors: CVSS, EPSS, KEV status, exploit availability, source reliability.
- **AI Summaries:** Worker generates summaries for items missing `ai_summary` every 5 minutes.
- **Caching:** Dashboard stats cached in Redis with TTL.

---

## Deployment

See [WORKFLOW.md](WORKFLOW.md) for full deployment walkthrough.

### CI/CD — Auto-Deploy on Push

Every `git push` to `main` triggers: **Lint → SSH Deploy to Hostinger VPS**.

**One-time setup:**

1. **Prepare the VPS** (SSH into Hostinger KVM):
   ```bash
   ssh root@<YOUR_VPS_IP>
   bash -s < <(curl -fsSL https://raw.githubusercontent.com/manishjnv/ti-platform/main/scripts/server-setup.sh)
   # Or: clone repo first, then run: bash scripts/server-setup.sh
   ```

2. **Generate an SSH key for GitHub Actions** (on the VPS):
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/github_deploy -N ""
   cat ~/.ssh/github_deploy.pub >> /home/deploy/.ssh/authorized_keys
   cat ~/.ssh/github_deploy   # Copy this private key
   ```

3. **Add GitHub Secrets** at `github.com/manishjnv/ti-platform/settings/secrets/actions`:

   | Secret | Value |
   |--------|-------|
   | `DEPLOY_HOST` | Your Hostinger VPS IP address |
   | `DEPLOY_USER` | `deploy` |
   | `DEPLOY_SSH_KEY` | The private key from step 2 |

4. **Push to main** — deployment runs automatically:
   ```bash
   git add -A && git commit -m "deploy" && git push origin main
   ```

**Manual deploy** (SSH into VPS directly):
```bash
ssh deploy@<YOUR_VPS_IP>
/opt/ti-platform/scripts/deploy.sh
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Feeds not syncing | Check `docker compose logs worker`. Verify API keys in `.env`. |
| Login not working | In dev: set `DEV_BYPASS_AUTH=true` in `.env`. In prod: verify CF Access config. |
| Session expired | Sessions last 8 hours by default. Adjust `JWT_EXPIRE_MINUTES` in `.env`. |
| OpenSearch index missing | API auto-creates on startup — check `:9200/_cluster/health` |
| TimescaleDB hypertable errors | Run `psql -f db/schema.sql` manually |
| AI summaries not appearing | Verify `AI_API_URL` is reachable from worker container |
| UI not loading | Check `docker compose logs ui` — rebuild with `docker compose build ui` |

---

## 🔐 Login & Authentication

### Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `DEV_BYPASS_AUTH` | Skip SSO, auto-login as dev admin | `true` in dev compose |
| `JWT_EXPIRE_MINUTES` | Session duration | `480` (8 hours) |
| `CF_ACCESS_TEAM_NAME` | Cloudflare Zero Trust team name | — (production only) |
| `CF_ACCESS_AUD` | Cloudflare Access audience tag | — (production only) |

### Auth Modes

| Mode | When | How |
|------|------|-----|
| **Dev Bypass** | `DEV_BYPASS_AUTH=true` or `ENVIRONMENT=development` | Click "Sign in (Dev Mode)" → auto-creates `dev@intelwatch.local` (admin) |
| **Cloudflare SSO** | `CF_ACCESS_TEAM_NAME` + `CF_ACCESS_AUD` set | Cloudflare Zero Trust intercepts → Google SSO → auto-provisions user |

### Auth Flow

```
Browser → /login → GET /api/v1/auth/config → determine auth method
  ├── Dev Mode:  POST /auth/login → auto-create dev user → set iw_session cookie → /dashboard
  └── SSO Mode:  Cloudflare redirect → SSO → POST /auth/login (with CF headers) → set iw_session cookie → /dashboard

Protected routes: AuthGuard → GET /auth/session → valid? → render : redirect to /login
Logout: POST /auth/logout → revoke Redis session → clear cookie → /login
```

### Key Details

- **Cookie:** `iw_session` — HttpOnly, SameSite=Lax, 8-hour TTL
- **Session store:** Redis (server-side revocable)
- **Protected routes:** All `(app)/*` pages wrapped in `AuthGuard` component
- **Root `/`** redirects to `/login`

---

## 📚 Documentation Index

Detailed documentation is maintained in the `docs/` folder. Each document is a **living document** updated as the platform evolves.

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Project overview, standards, quick start (this file) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, service topology, data model, security layers |
| [docs/TECHNOLOGY.md](docs/TECHNOLOGY.md) | Full technology stack, library rationale, version matrix |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Feed & integration requirements — all planned data sources with endpoints, status, and coverage matrix |
| [WORKFLOW.md](WORKFLOW.md) | Operations guide — deployment, CI/CD, Cloudflare Tunnel setup |

> **Rule:** When adding a new feature or integration, create or update the relevant doc in `docs/`.

---

## License

Private — All rights reserved.
