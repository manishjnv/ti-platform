# IntelWatch TI Platform — Workflow & Operations Guide

> **Architecture & data model** → [ARCHITECTURE.md](ARCHITECTURE.md) · **Technology stack** → [TECHNOLOGY.md](TECHNOLOGY.md) · **Feed integrations** → [INTEGRATION.md](INTEGRATION.md)

## Table of Contents

- [Local Development](#local-development)
- [Production Deployment](#production-deployment-hostinger-kvm-2)
- [Key Paths](#key-paths)
- [Troubleshooting](#troubleshooting)

---

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

> **Data flow & feed connectors** → [ARCHITECTURE.md](ARCHITECTURE.md) · [INTEGRATION.md](INTEGRATION.md)

---

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

| Problem | Solution |
|---------|----------|
| Feeds not syncing | Check `docker compose logs worker`. Verify API keys in `.env`. |
| Login not working (dev) | Set `DEV_BYPASS_AUTH=true` in `.env`, restart API. |
| Login not working (prod) | Verify `CF_ACCESS_TEAM_NAME` and `CF_ACCESS_AUD` in `.env`. Check Cloudflare Access config. |
| Auth bypass leaking to prod | Ensure `DEV_BYPASS_AUTH` is **not** `true` in production `.env`. |
| Session expired | Sessions last 8 hours by default. Adjust `JWT_EXPIRE_MINUTES`. |
| OpenSearch index missing | API auto-creates on startup. Check `:9200/_cluster/health`. |
| TimescaleDB hypertable errors | Run `psql -f db/schema.sql` manually if DB already exists. |
| AI summaries not appearing | Verify `AI_API_URL` is reachable from worker container. Check `docker compose logs worker`. |
| UI not loading | Check `docker compose logs ui`. Rebuild with `docker compose build ui`. |
| Docker Hub unreachable | Use Google mirror: `docker pull mirror.gcr.io/library/python:3.12-slim && docker tag mirror.gcr.io/library/python:3.12-slim python:3.12-slim` |
