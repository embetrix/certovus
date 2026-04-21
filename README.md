# Certovus

Let's Encrypt certificate broker for embedded devices. Devices send CSRs over
HTTPS; Certovus handles ACME DNS-01 challenges on their behalf via Cloudflare.
Devices never hold DNS credentials and never need inbound connectivity.

---

## Quickstart

```bash
cp .env.example .env          # review defaults — no changes needed for dev
make dev                      # starts pebble + nginx + broker
make test                     # unit tests + e2e flow against pebble
make down                     # tear down the stack
```

The full stack should be green in under 5 minutes on a cold Docker pull.

---

## Architecture

```
Multiple LANs                      Public VPS (broker.example.com)
─────────────                      ─────────────────────────────────
                                   ┌────────────────────────────────┐
Device A ─────┐                    │  UFW / fail2ban                │
Device B ─────┼── HTTPS ─────────►│  nginx (:443)                  │
Device C ─────┘   Bearer token     │    - LE cert via HTTP-01       │
                                   │  gunicorn (127.0.0.1:8080)     │
                                   │    - SQLite: devices, certs,   │
                                   │      audit log                 │
                                   │    - ACME client (in-process)  │
                                   │    - DNS adapter (Cloudflare)  │
                                   └──────────┬─────────────────────┘
                                              │ ACME + DNS API
                                              ▼
                                   Let's Encrypt + Cloudflare
```

### Auth model

Each device is provisioned with a random 32-byte Bearer token. The broker
stores only its SHA-256 fingerprint — the raw token is printed once at
provision time and never stored. Devices include it in every request:

```
Authorization: Bearer <token>
```

---

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Token leaked from device | Revoke via `certovus revoke <fingerprint>`; all future sign requests rejected |
| Token brute-forced | 64-hex token = 256 bits entropy; rate limiting at nginx + broker |
| Rogue CSR for unowned domain | `devices.hostnames` exact-match allowlist; CSR SAN checked against it |
| Global issuance abuse | Configurable rolling-window global cap (`RATE_GLOBAL`, default 50/week) |
| DB compromised | Only SHA-256 fingerprints stored, not raw tokens |
| ACME credentials leaked | Cloudflare token scoped to `dns_zone:edit` for one zone only |

The broker never touches device private keys. CSR subject and SANs come from
the device; the broker only checks that the SANs are in the device's allowlist.

---

## Provisioning a new device

```bash
# On the admin workstation (requires certovus CLI in PATH):
certovus provision \
    <cn> \
    --hostnames "device.example.com" \
    --label "living room sensor"

# Output:
# Provisioned device fingerprint: abc123...
# Token (shown once — store securely):
# 7f3a...
```

Flash the token into the device firmware's secure storage. The CN and
hostnames must match exactly what the device will put in its CSR.

To list all provisioned devices:

```bash
certovus devices        # active only
certovus devices --all  # including revoked
```

---

## Running a device

The device sends a PKCS#10 CSR (PEM) and receives a signed PEM chain:

```bash
curl -X POST https://broker.example.com/sign \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"csr": "<PEM>"}' \
| jq -r .cert > device.crt
```

Certificates are valid for ~90 days (Let's Encrypt default). The broker
returns a cached cert if more than 30 days remain; otherwise it re-issues.
Per-device rate limit: 1 issuance per 24 hours (configurable, bypassed when
the current cert has ≤30 days left).

---

## Switching staging → prod

Staging and production run the same binary. The only difference is the
`CERTOVUS_ENV` and ACME directory URL in `/etc/certovus/env`:

```bash
# staging
CERTOVUS_ENV=staging
PEBBLE_URL=https://acme-staging-v02.api.letsencrypt.org/directory

# production
CERTOVUS_ENV=production
PEBBLE_URL=https://acme-v02.api.letsencrypt.org/directory
```

After changing the env file: `systemctl restart certovus`.

When graduating from staging to production, delete the staging ACME account
key (`/data/certovus/acme_account.key`) so a fresh account is registered
against the production directory.

---

## Revocation runbook

```bash
# Revoke a device (blocks all future sign requests immediately):
certovus revoke <fingerprint> --reason "key compromise"

# Re-enable a mistakenly revoked device:
certovus unrevoke <fingerprint>

# View recent audit events for a device:
certovus audit --device <fingerprint> --limit 20
```

To also revoke the device's current certificate at the ACME CA (optional —
revocation via ACME does not prevent the device from getting a new cert):

```bash
# The cert PEM is stored in the DB:
certovus certs <fingerprint>   # prints stored certs with serial numbers
```

---

## VPS deployment

### Prerequisites

- Ubuntu 22.04 or 24.04 VPS with a public IP
- DNS A record for your broker domain pointing to the VPS
- Cloudflare API token scoped to `Zone:DNS:Edit` for the target zone

### Install

```bash
export CERTOVUS_DOMAIN=broker.example.com
export CERTOVUS_REPO=https://github.com/yourusername/certovus.git
curl -fsSL https://raw.githubusercontent.com/yourusername/certovus/main/deploy/install.sh | bash
```

The script:
1. Installs Python 3.12, nginx, certbot
2. Creates a `certovus` system user
3. Clones the repo to `/opt/certovus` and installs into a venv
4. Creates `/etc/certovus/env` with placeholder values
5. Installs and enables the systemd service
6. Configures nginx and obtains a TLS cert via certbot HTTP-01

After the script completes, edit `/etc/certovus/env`:

```bash
CLOUDFLARE_API_TOKEN=<your token>
CLOUDFLARE_ZONE_ID=<your zone id>
```

Then restart: `systemctl restart certovus`

### Updating

```bash
git -C /opt/certovus pull --ff-only
/opt/certovus/venv/bin/pip install -e /opt/certovus
systemctl restart certovus
```

### Firewall (UFW example)

```bash
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (certbot renewal)
ufw allow 443/tcp   # HTTPS (broker API)
ufw enable
```

---

## Backup strategy

The only stateful artifact is the SQLite database at `BROKER_DB_PATH`
(default `/data/certovus/certovus.db`). Back it up daily:

```bash
# Consistent snapshot using SQLite's .backup command (safe under WAL mode):
sqlite3 /data/certovus/certovus.db ".backup /tmp/certovus-$(date +%F).db"
```

Restore by stopping the service, replacing the DB file, and restarting:

```bash
systemctl stop certovus
cp certovus-backup.db /data/certovus/certovus.db
chown certovus:certovus /data/certovus/certovus.db
systemctl start certovus
```

The ACME account key (`/data/certovus/acme_account.key`) should also be
backed up. If lost, delete it and restart — the broker will register a new
account automatically (existing device certs are unaffected).

---

## Rotation schedule

| Item | Frequency | How |
|------|-----------|-----|
| Broker TLS cert | Auto, certbot renews at 60 days | `systemctl status certbot.timer` |
| Device certs | Auto, devices request renewal via `/sign` | Cache threshold 30 days |
| ACME account key | On compromise only | Delete `/data/certovus/acme_account.key`, restart |
| Cloudflare API token | Annually or on compromise | Update `/etc/certovus/env`, restart |
| Device tokens | On compromise | `certovus revoke` + re-provision |
