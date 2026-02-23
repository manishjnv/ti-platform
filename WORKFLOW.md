# IntelWatch TI Platform — Workflow Guide

## Architecture Overview

```
┌─────────────┐   Cloudflare Tunnel    ┌────────────────────────────────────────────┐
│  Browser     │ ─────────────────────► │  Docker Host                               │
│  (SSO via    │   intelwatch.trendsmap.in      │                                            │
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
git clone https://github.com/manishjnv/ti-platform.git && cd ti-platform
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

## Production Deployment (Hostinger KVM 2)

**Server:** Hostinger KVM 2 — 2 CPU, 8 GB RAM, 100 GB SSD, Ubuntu 22.04+

### Step 1 — Initial Server Setup (one-time)

```bash
# SSH into VPS as root
ssh root@<YOUR_VPS_IP>

# Run the automated setup script
bash -s < <(curl -fsSL https://raw.githubusercontent.com/manishjnv/ti-platform/main/scripts/server-setup.sh)

# Or clone manually and run:
git clone https://github.com/manishjnv/ti-platform.git /opt/ti-platform
bash /opt/ti-platform/scripts/server-setup.sh
```

This installs Docker, creates a `deploy` user, clones the repo, generates a `SECRET_KEY`, and creates `.env`.

### Step 2 — Configure Production `.env`

```bash
nano /opt/ti-platform/.env
```

| Variable | Action |
|----------|--------|
| `ENVIRONMENT` | Set to `production` (auto-set by setup script) |
| `SECRET_KEY` | Auto-generated — leave as-is |
| `POSTGRES_PASSWORD` | Change to a strong random password |
| `DEV_BYPASS_AUTH` | `false` (auto-set by setup script) |
| `DOMAIN` | `intelwatch.trendsmap.in` |
| `DOMAIN_UI` | `https://intelwatch.trendsmap.in` |
| `DOMAIN_API` | `https://intelwatch-api.trendsmap.in` |
| `CF_ACCESS_TEAM_NAME` | Your Cloudflare Zero Trust team name |
| `CF_ACCESS_AUD` | Your Cloudflare Access audience tag |
| Feed API keys | Already set from `.env.example` if copied |

### Step 3 — First Deploy

```bash
sudo -u deploy /opt/ti-platform/scripts/deploy.sh

# Verify
curl -s http://localhost:8000/api/v1/health | jq .
docker compose -f /opt/ti-platform/docker-compose.yml ps
```

### Step 4 — Set Up Cloudflare Tunnel

Follow instructions in `cloudflare/tunnel-config.yml`:
1. Install `cloudflared` on VPS
2. `cloudflared tunnel login` → select `trendsmap.in` zone
3. `cloudflared tunnel create intelwatch`
4. Route DNS: `cloudflared tunnel route dns intelwatch intelwatch.trendsmap.in`
5. Route DNS: `cloudflared tunnel route dns intelwatch intelwatch-api.trendsmap.in`
6. Create `/etc/cloudflared/config.yml` (see `cloudflare/tunnel-config.yml`)
7. `sudo cloudflared service install && sudo systemctl start cloudflared`

### Step 5 — Set Up CI/CD (GitHub Actions)

The pipeline in `.github/workflows/ci.yml`:
1. **PR/push** → lint Python (ruff) + TypeScript (tsc)
2. **Main push** → SSH deploy to VPS → `scripts/deploy.sh`

**Generate SSH key for GitHub Actions:**
```bash
ssh-keygen -t ed25519 -f ~/.ssh/github_deploy -N ""
cat ~/.ssh/github_deploy.pub >> /home/deploy/.ssh/authorized_keys
cat ~/.ssh/github_deploy   # Copy this private key
```

**Add GitHub Secrets** at [repo settings](https://github.com/manishjnv/ti-platform/settings/secrets/actions):

| Secret | Value |
|--------|-------|
| `DEPLOY_HOST` | Your Hostinger VPS IP address |
| `DEPLOY_USER` | `deploy` |
| `DEPLOY_SSH_KEY` | The private key content from above |

**Test:** Push to main → Actions tab shows lint + deploy pipeline running.

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
