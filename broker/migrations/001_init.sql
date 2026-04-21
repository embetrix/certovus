-- Certovus initial schema.
-- All timestamps are UTC ISO 8601 text. JSON arrays stored as TEXT.
-- Run via the migrations runner in broker/db.py — never execute manually.

-- ── devices ───────────────────────────────────────────────────────────────────
-- One row per provisioned device, keyed by SHA-256 of the device's bearer token.
-- Authentication: device sends Authorization: Bearer <token>; broker computes
-- SHA-256 and looks up this column.  The raw token is never stored.
CREATE TABLE IF NOT EXISTS devices (
    fingerprint     TEXT PRIMARY KEY,               -- SHA-256(bearer_token) hex
    cn              TEXT NOT NULL,
    hostnames       TEXT NOT NULL DEFAULT '[]',     -- JSON array of exact-match FQDNs
    label           TEXT NOT NULL DEFAULT '',
    client_cert_pem TEXT,                           -- reserved for future mTLS upgrade; nullable
    provisioned_at  TEXT NOT NULL,
    provisioned_by  TEXT NOT NULL,
    revoked_at      TEXT,
    revoked_by      TEXT,
    revoked_reason  TEXT,
    notes           TEXT,
    last_seen_at    TEXT,
    last_seen_ip    TEXT
);

-- Speeds up auth checks which always filter to active devices.
CREATE INDEX IF NOT EXISTS idx_devices_active
    ON devices (fingerprint)
 WHERE revoked_at IS NULL;

-- CN must be unique across all devices (active or revoked).
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_cn
    ON devices (cn);

-- ── audit_log ─────────────────────────────────────────────────────────────────
-- Append-only event stream. Application code never UPDATEs or DELETEs rows here.
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    event       TEXT NOT NULL,
    device_fp   TEXT REFERENCES devices (fingerprint) ON DELETE SET NULL,
    device_cn   TEXT,
    actor       TEXT NOT NULL,                      -- "device:<cn>" | "admin:<name>" | "system"
    source_ip   TEXT,
    user_agent  TEXT,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    details     TEXT,                               -- JSON object or NULL
    request_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit_log (ts);
CREATE INDEX IF NOT EXISTS idx_audit_device_fp ON audit_log (device_fp);
CREATE INDEX IF NOT EXISTS idx_audit_event     ON audit_log (event);

-- ── issued_certs ──────────────────────────────────────────────────────────────
-- One row per successful ACME issuance. Never deleted; used for cache + rate limits.
CREATE TABLE IF NOT EXISTS issued_certs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_fp      TEXT NOT NULL REFERENCES devices (fingerprint),
    cn             TEXT NOT NULL,
    hostnames      TEXT NOT NULL DEFAULT '[]',      -- JSON array
    serial         TEXT NOT NULL,                   -- hex string from signed leaf cert
    fingerprint    TEXT NOT NULL,                   -- SHA-256 of leaf cert DER (hex)
    csr_hash       TEXT NOT NULL,                   -- stable hash for cache lookups
    issued_at      TEXT NOT NULL,
    not_before     TEXT NOT NULL,
    not_after      TEXT NOT NULL,
    acme_order_url TEXT,
    cert_pem       TEXT NOT NULL                    -- full PEM chain (leaf + intermediates)
);

CREATE INDEX IF NOT EXISTS idx_certs_device_fp ON issued_certs (device_fp);
CREATE INDEX IF NOT EXISTS idx_certs_csr_hash  ON issued_certs (csr_hash);
CREATE INDEX IF NOT EXISTS idx_certs_not_after ON issued_certs (not_after);
CREATE INDEX IF NOT EXISTS idx_certs_issued_at ON issued_certs (issued_at);
