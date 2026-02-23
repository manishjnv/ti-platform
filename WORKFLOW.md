# Threat Intelligence Platform — Workflow Guide

## Architecture Overview

```
┌─────────────┐   Cloudflare Tunnel    ┌────────────────────────────────────────────┐
│  Browser     │ ─────────────────────► │  Docker Host                               │
│  (SSO via    │   ti.trendsmap.in      │                                            │
│  Zero Trust) │                        │  ┌──────┐  ┌──────┐  ┌───────────────┐    │
└─────────────┘                        │  │  UI  │  │  API │  │  Worker +     │    │
                                        │  │ :3000│→ │ :8000│  │  Scheduler    │    │
                                        │  └──────┘  └──┬───┘  └───────┬───────┘    │
                                        │               │              │             │
                                        │  ┌────────────┴──────────────┴──────────┐  │
                                        │  │  PostgreSQL │ Redis │ OpenSearch     │  │
                                        │  └──────────────────────────────────────┘  │
                                        └────────────────────────────────────────────┘
```

## Local Development

### Prerequisites
- Docker & Docker Compose v2
- (Optional) Python 3.12, Node 20 for running outside Docker

### Quick Start

```bash
# 1. Clone and configure
git clone <repo-url> && cd ti-platform
cp .env.example .env
# Edit .env — set DEV_BYPASS_AUTH=true for local dev

# 2. Start everything
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# 3. Access
# UI:  http://localhost:3000
# API: http://localhost:8000/api/v1/health
# OpenSearch: http://localhost:9200
```

### Hot-Reload (Dev Override)
The `docker-compose.dev.yml` overlay:
- Mounts `api/` and `worker/` into containers for live reload
- Runs uvicorn with `--reload`
- Sets `DEV_BYPASS_AUTH=true` (skips Cloudflare header check)
- Mounts `ui/src/` for Next.js hot module replacement

### Running Without Docker
```bash
# Terminal 1 — Data stores
docker compose up postgres redis opensearch

# Terminal 2 — API
cd api && pip install -e ".[dev]"
DEV_BYPASS_AUTH=true uvicorn app.main:app --reload --port 8000

# Terminal 3 — Worker
cd .. && python -m worker.worker

# Terminal 4 — Scheduler
python -m worker.scheduler

# Terminal 5 — UI
cd ui && npm install && npm run dev
```

## Production Deployment

### 1. Provision Host
Any VPS with Docker (2 vCPU, 4 GB RAM minimum for all containers).

### 2. Configure Environment
```bash
ssh deploy@your-host
git clone <repo> /opt/ti-platform && cd /opt/ti-platform
cp .env.example .env
# Fill in ALL values — especially:
#   - Feed API keys (NVD_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY)
#   - CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD
#   - AI endpoint if using summaries
#   - Strong POSTGRES_PASSWORD
```

### 3. Deploy
```bash
docker compose up -d --build
# Verify
docker compose logs -f api
curl -s http://localhost:8000/api/v1/health | jq .
```

### 4. Set Up Cloudflare Tunnel
Follow instructions in `cloudflare/tunnel-config.yml`:
1. Create tunnel via `cloudflared tunnel create`
2. Route DNS records
3. Configure Zero Trust Application (Google SSO)
4. Start tunnel (standalone or via Docker)

### 5. CI/CD (GitHub Actions)
The pipeline in `.github/workflows/ci.yml`:
1. **PR/push** → lint Python (ruff) + TypeScript (tsc)
2. **Main push** → build & push 3 Docker images to GHCR
3. **Deploy** → SSH to prod, `git pull`, `docker compose up -d`

Set these GitHub Secrets:
| Secret | Description |
|--------|-------------|
| `DEPLOY_HOST` | Production host IP/hostname |
| `DEPLOY_USER` | SSH username |
| `DEPLOY_SSH_KEY` | SSH private key |

## Data Flow

1. **Scheduler** enqueues feed-sync jobs on cron intervals (KEV 5m, NVD 15m, etc.)
2. **Worker** dequeues jobs → calls feed connectors → normalizes data
3. Items are scored (`compute_risk_score()`), stored in PostgreSQL, indexed in OpenSearch
4. **Worker** also generates AI summaries for items without one (every 5 minutes)
5. **API** serves paginated feeds, search, dashboard stats (cached in Redis)
6. **UI** renders the data with 30-60s auto-refresh on key pages

## Feed Connectors

| Feed | Source | Frequency | API Key Required |
|------|--------|-----------|-----------------|
| CISA KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 5 min | No |
| NVD | https://services.nvd.nist.gov/rest/json/cves/2.0 | 15 min | Optional (higher rate) |
| URLhaus | https://urlhaus.abuse.ch/downloads/csv_recent/ | 5 min | No |
| AbuseIPDB | https://api.abuseipdb.com/api/v2/blacklist | 15 min | Yes |
| OTX | https://otx.alienvault.com/api/v1/pulses/subscribed | 30 min | Yes |

## Key Paths

| Component | Path |
|-----------|------|
| DB Schema | `db/schema.sql` |
| API App | `api/app/main.py` |
| Feed Connectors | `api/app/services/feeds/` |
| Worker Tasks | `worker/tasks.py` |
| Scheduler | `worker/scheduler.py` |
| UI Pages | `ui/src/app/(app)/` |
| Docker | `docker/`, `docker-compose.yml` |
| Cloudflare | `cloudflare/tunnel-config.yml` |
| CI/CD | `.github/workflows/ci.yml` |

## Troubleshooting

**Feeds not syncing**: Check `docker compose logs worker`. Ensure API keys are set in `.env`.

**Auth bypass in prod**: Make sure `DEV_BYPASS_AUTH` is NOT set to `true` in production `.env`.

**OpenSearch index missing**: The API auto-creates the index on startup (`ensure_index()`). Check OpenSearch health at `:9200/_cluster/health`.

**TimescaleDB hypertable errors**: The `db/schema.sql` DDL is applied on first postgres start. If the DB already exists, run `psql -f db/schema.sql` manually.

**AI summaries not appearing**: Verify `AI_API_BASE_URL` is reachable from the worker container. Check `docker compose logs worker` for timeout errors.
