#!/usr/bin/env bash
# =============================================================================
# Bootstrap Let's Encrypt certificates for the ASM nginx reverse proxy.
#
# What it does:
#   1. Creates a throwaway self-signed cert at the path nginx expects so the
#      nginx container can actually start (chicken-and-egg fix).
#   2. Starts nginx (which now has a cert to load).
#   3. Deletes the dummy cert.
#   4. Asks Let's Encrypt for the real cert via the HTTP-01 webroot challenge
#      (nginx serves /.well-known/acme-challenge/ from the shared volume).
#   5. Reloads nginx so it picks up the real cert.
#   6. The certbot container then runs in the background renewing every 12h,
#      and nginx auto-reloads every 6h to pick up renewals.
#
# Usage (run from repo root, on the EC2 instance):
#   1. Set DOMAIN and LETSENCRYPT_EMAIL in .env
#   2. Make sure DNS for $DOMAIN points at this server's public IP
#   3. Make sure ports 80 and 443 are open in the security group
#   4. Run: sudo bash scripts/init-letsencrypt.sh
#
# Re-running is safe: it will skip cert issuance if a real cert already exists,
# unless you pass --force.
# =============================================================================

set -euo pipefail

# ----- Locate repo root and load .env -----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
else
  echo "ERROR: .env not found in ${REPO_ROOT}" >&2
  echo "Create one with at least: DOMAIN=your.domain.com  LETSENCRYPT_EMAIL=you@example.com" >&2
  exit 1
fi

# ----- Required env -----
DOMAIN="${DOMAIN:-}"
EMAIL="${LETSENCRYPT_EMAIL:-}"
STAGING="${LETSENCRYPT_STAGING:-0}"   # set to 1 to use staging while testing
RSA_KEY_SIZE=4096

if [[ -z "${DOMAIN}" || "${DOMAIN}" == "localhost" ]]; then
  echo "ERROR: DOMAIN must be set in .env to a real DNS name (got: '${DOMAIN}')" >&2
  exit 1
fi
if [[ -z "${EMAIL}" ]]; then
  echo "ERROR: LETSENCRYPT_EMAIL must be set in .env" >&2
  exit 1
fi

# ----- Args -----
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --staging) STAGING=1 ;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

# ----- Pick docker compose binary -----
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "ERROR: docker compose / docker-compose not found" >&2
  exit 1
fi

CERT_PATH="/etc/letsencrypt/live/${DOMAIN}"

echo "============================================================"
echo "  Domain:           ${DOMAIN}"
echo "  Email:            ${EMAIL}"
echo "  Staging:          ${STAGING}  (1 = use Let's Encrypt staging)"
echo "  Force re-issue:   ${FORCE}"
echo "  Compose binary:   ${DC}"
echo "============================================================"

# ----- 0. Quick existing-cert short-circuit -----
existing_check() {
  $DC run --rm --no-deps --entrypoint sh certbot -c "test -f ${CERT_PATH}/fullchain.pem && test -f ${CERT_PATH}/privkey.pem"
}

if [[ "${FORCE}" -eq 0 ]] && existing_check >/dev/null 2>&1; then
  echo ""
  echo "✓ A real certificate already exists at ${CERT_PATH}"
  echo "  Skipping issuance. Re-run with --force to replace it."
  echo ""
  echo "Bringing the stack up..."
  $DC up -d
  echo ""
  echo "Done. Site should be live at: https://${DOMAIN}"
  exit 0
fi

# ----- 1. Make sure /etc/letsencrypt has the recommended TLS options file -----
# This is just a copy of Certbot's recommended Mozilla intermediate config and
# DH params. We download via certbot helper (one-shot container).
echo ""
echo "[1/5] Ensuring Let's Encrypt TLS option files exist..."
$DC run --rm --no-deps --entrypoint sh certbot -c "
  set -e
  mkdir -p /etc/letsencrypt
  if [ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]; then
    wget -qO /etc/letsencrypt/options-ssl-nginx.conf \
      https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf
  fi
  if [ ! -f /etc/letsencrypt/ssl-dhparams.pem ]; then
    openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
  fi
"

# ----- 2. Create a dummy self-signed cert so nginx can start -----
echo ""
echo "[2/5] Creating dummy self-signed cert for ${DOMAIN} so nginx can start..."
$DC run --rm --no-deps --entrypoint sh certbot -c "
  set -e
  mkdir -p ${CERT_PATH}
  openssl req -x509 -nodes -newkey rsa:${RSA_KEY_SIZE} -days 1 \
    -keyout '${CERT_PATH}/privkey.pem' \
    -out    '${CERT_PATH}/fullchain.pem' \
    -subj   '/CN=localhost'
"

# ----- 3. Start nginx (and its dependencies) -----
echo ""
echo "[3/5] Starting nginx + dependencies..."
$DC up -d --force-recreate nginx

# Give nginx a couple seconds to come up
sleep 3

# ----- 4. Delete the dummy cert and request the real one -----
echo ""
echo "[4/5] Deleting dummy cert and requesting real Let's Encrypt cert..."
$DC run --rm --no-deps --entrypoint sh certbot -c "
  rm -rf /etc/letsencrypt/live/${DOMAIN} \
         /etc/letsencrypt/archive/${DOMAIN} \
         /etc/letsencrypt/renewal/${DOMAIN}.conf
"

STAGING_FLAG=""
if [[ "${STAGING}" -eq 1 ]]; then
  STAGING_FLAG="--staging"
  echo "  ⚠  Using Let's Encrypt STAGING server (cert will not be trusted by browsers)"
fi

$DC run --rm --no-deps certbot certonly \
  --webroot -w /var/www/certbot \
  ${STAGING_FLAG} \
  --email "${EMAIL}" \
  --agree-tos \
  --no-eff-email \
  --rsa-key-size "${RSA_KEY_SIZE}" \
  --force-renewal \
  -d "${DOMAIN}"

# ----- 5. Reload nginx to pick up the real cert -----
echo ""
echo "[5/5] Reloading nginx with real certificate..."
$DC exec nginx nginx -s reload

# Make sure the renewing certbot loop is running
$DC up -d certbot

echo ""
echo "============================================================"
echo "  ✓ Done."
echo "  Site:    https://${DOMAIN}"
echo "  Backend: https://${DOMAIN}/api/v1/..."
echo "  Docs:    https://${DOMAIN}/docs"
echo ""
echo "  Certificates auto-renew every 12h via the certbot container."
echo "  nginx auto-reloads every 6h to pick up renewals."
echo "============================================================"
