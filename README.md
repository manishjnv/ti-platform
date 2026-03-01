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

- [Architecture](#architecture)
- [Pages & Features](#pages--features)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Login & Authentication](#-login--authentication)
- [Documentation Index](#-documentation-index)

---

## Architecture

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

> **Deep dives:** [Architecture & Data Model](docs/ARCHITECTURE.md) · [Technology Stack](docs/TECHNOLOGY.md) · [Feed Integrations](docs/INTEGRATION.md)

---

## Pages & Features

| Page | Route | Description |
|------|-------|-------------|
| **Login** | `/login` | IntelWatch branded login — SSO redirect or dev bypass |
| **Dashboard** | `/dashboard` | KPI stat cards, threat level bar, severity/category donut charts, top risks table, feed status |
| **Threat Feed** | `/threats` | Severity filter pills, risk-sorted threat list, asset type breakdown |
| **Intel Items** | `/intel` | Paginated intel browser with filters, detail drill-down |
| **IOC Search** | `/search` | Full-text IOC search with type/severity/date filters, Live Internet Lookup (12+ sources), structured AI analysis |
| **IOC Database** | `/iocs` | Browse all IOCs with type filter pills, copy-to-clipboard, type distribution donut |
| **Analytics** | `/analytics` | Severity bar chart, category donut, geo/industry rankings, source reliability |
| **Geo View** | `/geo` | Geographic threat distribution, region drill-down, region-specific threat list |
| **Feed Status** | `/feeds` | Feed health monitor with status badges, error display, item counts |
| **Settings** | `/settings` | General, Security, Notifications, Appearance, Data & Storage, API Keys, Platform Setup |

**Shared components:** AuthGuard, StatCard, ThreatLevelBar, StructuredIntelCards (unified intel display), DonutChart, TrendLineChart, HorizontalBarChart, RankedDataList, FeedStatusPanel, Sidebar (4-section nav), Header bar (search, notifications, user menu).

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
# Edit .env — set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SECRET_KEY
```

### 2. Start All Services

```bash
# Production mode
docker compose up -d --build

# Development mode (hot reload — recommended for local dev)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

### 3. Verify

```bash
curl -s http://localhost:8000/api/v1/health | jq .
# Expected: {"status":"ok","postgres":true,"redis":true,"opensearch":true}

open http://localhost:3000   # UI — redirects to login
```

> **Full workflow:** Local dev, production deployment, Caddy reverse proxy, CI/CD → [docs/WORKFLOW.md](docs/WORKFLOW.md)

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
| `GOOGLE_CLIENT_ID` | **Yes** | Google OAuth 2.0 Client ID |
| `GOOGLE_CLIENT_SECRET` | **Yes** | Google OAuth 2.0 Client Secret |
| `JWT_EXPIRE_MINUTES` | No | Session duration in minutes (default: `480`) |
| `SMTP_HOST` | OTP | SMTP server host (e.g., `smtp.gmail.com`) |
| `SMTP_PORT` | OTP | SMTP port (default: `587`) |
| `SMTP_USER` | OTP | SMTP username |
| `SMTP_PASSWORD` | OTP | SMTP password |
| `SMTP_FROM_EMAIL` | OTP | Sender email (default: `noreply@intelwatch.in`) |
| `EMAIL_OTP_ENABLED` | No | Enable email OTP login (default: `false`) |
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

## API Reference

Base URL: `http://localhost:8000/api/v1`

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Service health check |
| `GET` | `/auth/config` | No | Auth method configuration |
| `GET` | `/auth/google/url` | No | Get Google OAuth redirect URL |
| `GET` | `/auth/google/callback` | No | Google OAuth callback (redirect from Google) |
| `POST` | `/auth/otp/send` | No | Send email OTP code |
| `POST` | `/auth/otp/verify` | No | Verify OTP and create session |
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

## 🔐 Login & Authentication

| Mode | When | How |
|------|------|-----|
| **Google OAuth** | `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` set | Click "Sign in with Google" → Google consent → redirect callback → session created |
| **Email OTP** | `EMAIL_OTP_ENABLED=true` + SMTP configured | Enter email → receive 6-digit code → verify → session created |

```
Browser → /login → GET /api/v1/auth/config → determine available auth methods
  ├── Google:  GET /auth/google/url → redirect to Google → callback → set cookie → /dashboard
  └── OTP:     POST /auth/otp/send → enter code → POST /auth/otp/verify → set cookie → /dashboard

Protected routes: AuthGuard → GET /auth/session → valid? → render : redirect /login
Logout: POST /auth/logout → revoke Redis session → clear cookie → /login
```

- **Cookie:** `iw_session` — HttpOnly, Secure, SameSite=Lax, 8-hour TTL
- **Session store:** Redis (server-side revocable)
- **Reverse proxy:** Caddy (automatic HTTPS via Let's Encrypt)
- **Protected routes:** All `(app)/*` pages wrapped in `AuthGuard`

---

## 📚 Documentation Index

All detailed docs live in `docs/`. Each is a **living document** updated as the platform evolves.

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Project overview, quick start, API reference (this file) |
| [docs/Instruction.md](docs/Instruction.md) | **Mandatory** engineering & development standards |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture, service topology, data model, security layers |
| [docs/TECHNOLOGY.md](docs/TECHNOLOGY.md) | Full technology stack, library rationale, version matrix |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | Feed & integration requirements — all planned data sources |
| [docs/WORKFLOW.md](docs/WORKFLOW.md) | Operations guide — local dev, deployment, CI/CD, Caddy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Multi-phase feature roadmap & progress tracker |

> **Rule:** When adding a new feature or integration, update the relevant doc in `docs/`.

---

## License

Private — All rights reserved.
