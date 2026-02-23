#!/bin/bash
# =============================================
# IntelWatch TI Platform — Deploy Script
# =============================================
# Called by GitHub Actions CI/CD or manually.
# Usage: /opt/ti-platform/scripts/deploy.sh
# =============================================
set -euo pipefail

APP_DIR="/opt/ti-platform"
COMPOSE_FILE="docker-compose.yml"
LOG_FILE="/opt/ti-platform/deploy.log"

cd "$APP_DIR"

echo "=======================================" | tee -a "$LOG_FILE"
echo " Deploying IntelWatch — $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "$LOG_FILE"
echo "=======================================" | tee -a "$LOG_FILE"

# ── 1. Pull latest code ───────────────────────────────
echo "[1/5] Pulling latest code..." | tee -a "$LOG_FILE"
git fetch origin main
git reset --hard origin/main
echo "  Commit: $(git rev-parse --short HEAD)" | tee -a "$LOG_FILE"

# ── 2. Build images ───────────────────────────────────
echo "[2/5] Building Docker images..." | tee -a "$LOG_FILE"
docker compose -f "$COMPOSE_FILE" build --parallel 2>&1 | tail -5 | tee -a "$LOG_FILE"

# ── 3. Restart services ───────────────────────────────
echo "[3/5] Starting services..." | tee -a "$LOG_FILE"
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans 2>&1 | tee -a "$LOG_FILE"

# ── 4. Wait for health checks ─────────────────────────
echo "[4/5] Waiting for health checks..." | tee -a "$LOG_FILE"
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    HEALTHY=$(docker compose ps --format json 2>/dev/null | grep -c '"healthy"' || true)
    TOTAL=$(docker compose ps --format json 2>/dev/null | wc -l || true)
    echo "  Health: $HEALTHY/$TOTAL services healthy ($ELAPSED s)" | tee -a "$LOG_FILE"
    if [ "$HEALTHY" -ge 3 ]; then
        break
    fi
    sleep 10
    ELAPSED=$((ELAPSED + 10))
done

# ── 5. Cleanup ─────────────────────────────────────────
echo "[5/5] Cleaning up old images..." | tee -a "$LOG_FILE"
docker image prune -f --filter "until=48h" 2>&1 | tail -1 | tee -a "$LOG_FILE"

# ── Summary ────────────────────────────────────────────
echo "" | tee -a "$LOG_FILE"
echo "Deploy complete! Services:" | tee -a "$LOG_FILE"
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | tee -a "$LOG_FILE"

# Quick health check
API_STATUS=$(curl -sf http://localhost:8000/api/v1/health | head -c 200 || echo "UNREACHABLE")
echo "" | tee -a "$LOG_FILE"
echo "API Health: $API_STATUS" | tee -a "$LOG_FILE"
echo "=======================================" | tee -a "$LOG_FILE"
