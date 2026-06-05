#!/bin/bash
# =============================================================================
# Push latest code and restart services on EC2
# =============================================================================
# Usage: ./scripts/push-to-ec2.sh <EC2_IP> [path/to/key.pem]
#
# Example:
#   ./scripts/push-to-ec2.sh 1.2.3.4 ~/.ssh/mykey.pem
# =============================================================================
set -euo pipefail

EC2_IP="${1:-}"
KEY_FILE="${2:-~/.ssh/id_rsa}"
APP_DIR="${APP_DIR:-/opt/asm}"
SSH_USER="${SSH_USER:-ubuntu}"

if [ -z "$EC2_IP" ]; then
  echo "Usage: $0 <EC2_IP> [path/to/key.pem]"
  exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
[ -f "$KEY_FILE" ] && SSH_OPTS="$SSH_OPTS -i $KEY_FILE"

echo "→ Deploying to $SSH_USER@$EC2_IP:$APP_DIR"

ssh $SSH_OPTS "$SSH_USER@$EC2_IP" bash <<EOF
  set -e
  cd $APP_DIR

  echo "[1/4] Pulling latest code..."
  git pull

  echo "[2/4] Rebuilding changed images (backend + oracle)..."
  docker compose build backend aegis-oracle

  echo "[3/4] Restarting services..."
  docker compose up -d --no-deps backend aegis-oracle frontend nginx

  echo "[4/4] Running Oracle DB migration..."
  docker exec asm_backend python scripts/migrate_add_oracle_columns.py --backfill 2>/dev/null || true

  echo ""
  echo "✓ Deploy complete. Service status:"
  docker compose ps
EOF
