# Certovus

Let's Encrypt certificate broker for embedded devices. Devices send CSRs over
mTLS; Certovus handles ACME DNS-01 challenges on their behalf via Cloudflare.
Devices never hold DNS credentials and never need inbound connectivity.

---

## Quickstart

```bash
cp .env.example .env          # review defaults — no changes needed for dev
make dev                      # starts pebble + challtestsrv + nginx + broker
make test                     # unit tests + e2e flow against pebble
make down                     # tear down the stack
```

The full stack should be green in under 5 minutes on a cold Docker pull.

---

## Architecture

```
Multiple LANs                      Public VPS (broker.embetrix.works)
─────────────                      ─────────────────────────────────
                                   ┌────────────────────────────────┐
Device A ─────┐                    │  UFW / fail2ban                │
Device B ─────┼── mTLS over ──────►│  nginx (:443)                  │
Device C ─────┘   public internet  │    - LE cert via HTTP-01       │
                                   │    - mTLS against Device CA    │
                                   │    - injects client cert PEM   │
                                   │  Flask broker (127.0.0.1:8080) │
                                   │    - SQLite: devices, audit,   │
                                   │      issued certs              │
                                   │    - ACME client (in-process)  │
                                   │    - DNS adapter (Cloudflare)  │
                                   └──────────┬─────────────────────┘
                                              │ ACME + DNS API
                                              ▼
                                   Let's Encrypt + Cloudflare
```

### Trust chain

```
Device CA (offline workstation)
  └── Device client certs (2-year, clientAuth EKU)
        └── mTLS authentication against broker

Let's Encrypt
  └── broker.embetrix.works TLS cert (HTTP-01, auto-renewed by certbot)
  └── dev-<id>.embetrix.works certs (DNS-01, brokered on device behalf)
```

---

## Threat model

_TODO (deliverable 18)_

---

## Provisioning a new device

_TODO (deliverable 18)_

---

## Running a device

_TODO (deliverable 18)_

---

## Switching staging → prod

_TODO (deliverable 18)_

---

## Revocation runbook

_TODO (deliverable 18)_

---

## VPS deployment

_TODO (deliverable 18)_

---

## Backup strategy

_TODO (deliverable 18)_

---

## Rotation schedule

_TODO (deliverable 18)_
