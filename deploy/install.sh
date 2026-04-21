#!/usr/bin/env bash
# VPS bootstrap for Certovus.
#
# Run once as root on a fresh Ubuntu 22.04/24.04 VPS:
#   curl -fsSL https://raw.githubusercontent.com/.../deploy/install.sh | \
#     CERTOVUS_DOMAIN=broker.example.com bash
#
# After this script completes:
#   1. Edit /etc/certovus/env with real credentials (Cloudflare token/zone, etc.)
#   2. Run: certovus provision <cn> --hostnames <h1,h2> --label "My device"
#   3. Give the printed token to the device firmware.
set -euo pipefail

DOMAIN="${CERTOVUS_DOMAIN:?Set CERTOVUS_DOMAIN=broker.example.com}"
REPO="${CERTOVUS_REPO:-https://github.com/yourusername/certovus.git}"
DATA_DIR="/data/certovus"
INSTALL_DIR="/opt/certovus"
ENV_FILE="/etc/certovus/env"
NGINX_CONF="/etc/nginx/sites-available/certovus"

# ── Sanity checks ─────────────────────────────────────────────────────────────

[[ "$(id -u)" -eq 0 ]] || { echo "Must run as root"; exit 1; }
command -v git  >/dev/null 2>&1 || apt-get install -y git
command -v curl >/dev/null 2>&1 || apt-get install -y curl

# ── System packages ───────────────────────────────────────────────────────────

apt-get update -q
apt-get install -y --no-install-recommends \
    python3.12 python3.12-venv python3.12-dev \
    build-essential libffi-dev libssl-dev \
    nginx certbot python3-certbot-nginx \
    sqlite3

# ── Certovus user ─────────────────────────────────────────────────────────────

if ! id certovus &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin certovus
fi

# ── Data directory ────────────────────────────────────────────────────────────

mkdir -p "$DATA_DIR"
chown certovus:certovus "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# ── Clone / update source ─────────────────────────────────────────────────────

if [[ -d "$INSTALL_DIR/.git" ]]; then
    git -C "$INSTALL_DIR" pull --ff-only
else
    git clone "$REPO" "$INSTALL_DIR"
fi
chown -R certovus:certovus "$INSTALL_DIR"

# ── Python virtualenv ─────────────────────────────────────────────────────────

python3.12 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip wheel
"$INSTALL_DIR/venv/bin/pip" install -e "$INSTALL_DIR"

# ── Environment file ──────────────────────────────────────────────────────────

mkdir -p /etc/certovus
chmod 0700 /etc/certovus

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<EOF
CERTOVUS_ENV=production
BROKER_DB_PATH=${DATA_DIR}/certovus.db
ACME_ACCOUNT_KEY_PATH=${DATA_DIR}/acme_account.key
PEBBLE_URL=https://acme-v02.api.letsencrypt.org/directory
CLOUDFLARE_API_TOKEN=REPLACE_ME
CLOUDFLARE_ZONE_ID=REPLACE_ME
RATE_PER_DEVICE=1
RATE_PER_DEVICE_HOURS=24
RATE_GLOBAL=50
RATE_GLOBAL_DAYS=7
LOG_LEVEL=INFO
EOF
    chmod 0600 "$ENV_FILE"
    chown certovus:certovus "$ENV_FILE"
    echo "IMPORTANT: edit $ENV_FILE and set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID"
fi

# ── systemd service ───────────────────────────────────────────────────────────

cp "$INSTALL_DIR/deploy/certovus.service" /etc/systemd/system/certovus.service
systemctl daemon-reload
systemctl enable certovus

# ── nginx ─────────────────────────────────────────────────────────────────────

export CERTOVUS_DOMAIN="$DOMAIN"
envsubst '${CERTOVUS_DOMAIN}' \
    < "$INSTALL_DIR/nginx/nginx.conf" \
    > "$NGINX_CONF"

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/certovus
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl reload nginx || systemctl start nginx

# ── TLS cert via certbot ──────────────────────────────────────────────────────

if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
    certbot --nginx \
        --non-interactive \
        --agree-tos \
        --register-unsafely-without-email \
        -d "$DOMAIN"
fi

# certbot auto-renewal is handled by the timer installed by the certbot package.
# Verify: systemctl status certbot.timer

# ── Start broker ──────────────────────────────────────────────────────────────

systemctl start certovus
systemctl status certovus --no-pager

echo ""
echo "Certovus installed. Verify:"
echo "  curl https://${DOMAIN}/health"
echo ""
echo "Next steps:"
echo "  1. Edit ${ENV_FILE} — set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID"
echo "  2. systemctl restart certovus"
echo "  3. certovus provision <cn> --hostnames <fqdn> --label 'device'"
