#!/bin/bash
# =============================================
# IntelWatch TI Platform — Initial Server Setup
# =============================================
# Run this ONCE on a fresh Ubuntu 22.04+ VPS (e.g. Hostinger KVM 2).
# Usage: ssh root@your-vps-ip 'bash -s' < scripts/server-setup.sh
# =============================================
set -euo pipefail

DEPLOY_USER="deploy"
APP_DIR="/opt/ti-platform"
REPO_URL="https://github.com/manishjnv/ti-platform.git"

echo "======================================="
echo " IntelWatch — Server Setup"
echo "======================================="

# ── 1. System updates ─────────────────────────────────
echo "[1/7] Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq

# ── 2. Install Docker ─────────────────────────────────
echo "[2/7] Installing Docker..."
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    echo "  Docker installed: $(docker --version)"
else
    echo "  Docker already installed: $(docker --version)"
fi

# ── 3. Install Docker Compose plugin ──────────────────
echo "[3/7] Verifying Docker Compose..."
if docker compose version &>/dev/null; then
    echo "  Docker Compose: $(docker compose version)"
else
    echo "  ERROR: Docker Compose plugin not found. Install manually."
    exit 1
fi

# ── 4. Create deploy user ─────────────────────────────
echo "[4/7] Creating deploy user..."
if id "$DEPLOY_USER" &>/dev/null; then
    echo "  User '$DEPLOY_USER' already exists"
else
    adduser --disabled-password --gecos "" "$DEPLOY_USER"
    usermod -aG docker "$DEPLOY_USER"
    echo "  Created user '$DEPLOY_USER' with Docker access"
fi

# Set up SSH key for deploy user (copy from root if exists)
if [ -f /root/.ssh/authorized_keys ]; then
    mkdir -p /home/$DEPLOY_USER/.ssh
    cp /root/.ssh/authorized_keys /home/$DEPLOY_USER/.ssh/
    chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh
    chmod 700 /home/$DEPLOY_USER/.ssh
    chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys
    echo "  SSH keys copied to $DEPLOY_USER"
fi

# ── 5. Clone repository ───────────────────────────────
echo "[5/7] Cloning repository..."
if [ -d "$APP_DIR" ]; then
    echo "  $APP_DIR already exists — skipping clone"
else
    git clone "$REPO_URL" "$APP_DIR"
    chown -R $DEPLOY_USER:$DEPLOY_USER "$APP_DIR"
    echo "  Cloned to $APP_DIR"
fi

# ── 6. Create .env from template ──────────────────────
echo "[6/7] Setting up environment..."
if [ -f "$APP_DIR/.env" ]; then
    echo "  .env already exists — skipping"
else
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    # Generate a random SECRET_KEY
    SECRET=$(openssl rand -hex 32)
    sed -i "s/change-me-in-production-use-openssl-rand-hex-32/$SECRET/" "$APP_DIR/.env"
    # Set production defaults
    sed -i 's/ENVIRONMENT=development/ENVIRONMENT=production/' "$APP_DIR/.env"
    sed -i 's/DEV_BYPASS_AUTH=true/DEV_BYPASS_AUTH=false/' "$APP_DIR/.env"
    chown $DEPLOY_USER:$DEPLOY_USER "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "  Created .env with random SECRET_KEY"
    echo "  ⚠  EDIT .env to set: POSTGRES_PASSWORD, CF_ACCESS_TEAM_NAME, CF_ACCESS_AUD, API keys"
fi

# ── 7. Make deploy script executable ──────────────────
echo "[7/7] Finalizing..."
chmod +x "$APP_DIR/scripts/deploy.sh"

echo ""
echo "======================================="
echo " Setup Complete!"
echo "======================================="
echo ""
echo " Next steps:"
echo "   1. Edit /opt/ti-platform/.env with your production values"
echo "   2. Run: sudo -u deploy /opt/ti-platform/scripts/deploy.sh"
echo "   3. Set up Cloudflare Tunnel (see cloudflare/tunnel-config.yml)"
echo "   4. Add GitHub Secrets for CI/CD (see README.md)"
echo ""
echo " VPS IP for GitHub Secret DEPLOY_HOST:"
hostname -I | awk '{print "   " $1}'
echo ""
