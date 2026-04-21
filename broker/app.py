"""Flask application factory for the Certovus broker.

All dependencies are injected via create_app() so the app is fully
testable without environment variables or real ACME/DNS connections.

Request lifecycle for POST /sign:
  1. Authenticate bearer token → look up device
  2. Parse and validate CSR
  3. Cache lookup (same CSR hash, >30 days remaining → return immediately)
  4. Rate limit check
  5. ACME issuance
  6. Record cert in DB, audit, touch last_seen
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from cryptography.hazmat.primitives.serialization import Encoding as CryptoEncoding
from cryptography.x509 import load_pem_x509_certificate
from flask import Flask, Response, g, jsonify, request

from broker.acme_client import ACMEClient
from broker.audit import AuditEntry, AuditLog, Event
from broker.cache import CertCache
from broker.csr import parse_csr, validate_hostnames
from broker.db import CertsDB, DevicesDB, IssuedCert
from broker.dns import DNSProvider
from broker.errors import ACMEError, CSRError, HostnameDeniedError, RateLimitError
from broker.rate_limit import RateLimiter

logger = logging.getLogger(__name__)


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _err(code: str, message: str, status: int) -> tuple[Response, int]:
    return jsonify({"error": code, "message": message}), status


def _extract_leaf_cert_meta(fullchain_pem: str) -> tuple[str, str, str, str]:
    """Return (serial_hex, cert_fp_hex, not_before_iso, not_after_iso) for the leaf cert."""
    lines = fullchain_pem.strip().splitlines()
    block: list[str] = []
    in_cert = False
    for line in lines:
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            in_cert = True
            block = [line]
        elif line.startswith("-----END CERTIFICATE-----"):
            block.append(line)
            break
        elif in_cert:
            block.append(line)
    cert = load_pem_x509_certificate("\n".join(block).encode())
    serial_hex = format(cert.serial_number, "x")
    cert_fp = hashlib.sha256(cert.public_bytes(CryptoEncoding.DER)).hexdigest()
    return serial_hex, cert_fp, cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat()


def create_app(
    *,
    acme_client: ACMEClient,
    dns_provider: DNSProvider,
    rate_limiter: RateLimiter,
    cache: CertCache,
    audit: AuditLog,
    devices_db: DevicesDB,
    certs_db: CertsDB,
) -> Flask:
    """Application factory — all dependencies injected for testability."""
    app = Flask(__name__)

    @app.before_request
    def _assign_request_context() -> None:
        g.request_id = str(uuid.uuid4())
        g.source_ip = request.remote_addr or "unknown"

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok"})

    @app.post("/sign")
    def sign() -> Response | tuple[Response, int]:
        # ── Auth ──────────────────────────────────────────────────────────────
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            audit.record(AuditEntry(
                event=Event.AUTH_MISSING_TOKEN,
                actor="anonymous",
                outcome="failure",
                source_ip=g.source_ip,
                request_id=g.request_id,
            ))
            return _err("missing_token", "Authorization header missing or not Bearer", 401)

        token = auth_header[len("Bearer "):]
        fp = _token_fingerprint(token)
        device = devices_db.get_by_fingerprint(fp)

        if device is None:
            audit.record(AuditEntry(
                event=Event.AUTH_UNKNOWN_TOKEN,
                actor="anonymous",
                outcome="failure",
                source_ip=g.source_ip,
                request_id=g.request_id,
            ))
            return _err("unknown_token", "Token not recognised", 401)

        if not device.is_active:
            audit.record(AuditEntry(
                event=Event.AUTH_REVOKED,
                actor=f"device:{device.cn}",
                outcome="failure",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
            ))
            return _err("device_revoked", "Device has been revoked", 403)

        audit.record(AuditEntry(
            event=Event.AUTH_SUCCESS,
            actor=f"device:{device.cn}",
            outcome="success",
            device_fp=device.fingerprint,
            device_cn=device.cn,
            source_ip=g.source_ip,
            request_id=g.request_id,
        ))

        # ── Parse request body ────────────────────────────────────────────────
        body = request.get_json(silent=True)
        if not body or "csr" not in body:
            return _err("invalid_request", "JSON body with 'csr' field required", 400)

        # ── Parse CSR ─────────────────────────────────────────────────────────
        try:
            parsed = parse_csr(body["csr"])
        except CSRError as exc:
            audit.record(AuditEntry(
                event=Event.SIGN_BAD_CSR,
                actor=f"device:{device.cn}",
                outcome="failure",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
                details={"reason": str(exc)},
            ))
            return _err("invalid_csr", str(exc), 400)

        # ── Validate hostnames ────────────────────────────────────────────────
        try:
            validate_hostnames(parsed, device.hostnames)
        except HostnameDeniedError as exc:
            audit.record(AuditEntry(
                event=Event.SIGN_HOSTNAME_DENIED,
                actor=f"device:{device.cn}",
                outcome="failure",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
                details={"reason": str(exc)},
            ))
            return _err("hostname_denied", str(exc), 403)

        # ── Cache hit ─────────────────────────────────────────────────────────
        cached = cache.get(device.fingerprint, parsed.csr_hash)
        if cached is not None:
            audit.record(AuditEntry(
                event=Event.SIGN_CACHE_HIT,
                actor=f"device:{device.cn}",
                outcome="success",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
                details={"serial": cached.serial},
            ))
            return jsonify({"cert": cached.cert_pem})

        # ── Rate limit ────────────────────────────────────────────────────────
        try:
            rate_limiter.check(device.fingerprint)
        except RateLimitError as exc:
            audit.record(AuditEntry(
                event=Event.SIGN_RATE_LIMITED,
                actor=f"device:{device.cn}",
                outcome="failure",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
                details={"reason": str(exc)},
            ))
            return _err("rate_limited", str(exc), 429)

        # ── ACME issuance ─────────────────────────────────────────────────────
        try:
            fullchain_pem = acme_client.issue(parsed.pem, dns_provider)
        except ACMEError as exc:
            logger.error("acme issuance failed for %s: %s", device.cn, exc)
            audit.record(AuditEntry(
                event=Event.SIGN_ACME_FAILED,
                actor=f"device:{device.cn}",
                outcome="failure",
                device_fp=device.fingerprint,
                device_cn=device.cn,
                source_ip=g.source_ip,
                request_id=g.request_id,
                details={"reason": str(exc)},
            ))
            return _err("acme_error", str(exc), 502)
        except Exception:
            logger.exception("unexpected error during issuance for %s", device.cn)
            return _err("internal_error", "Internal server error", 500)

        # ── Parse issued cert metadata ────────────────────────────────────────
        try:
            serial_hex, cert_fp, not_before, not_after = _extract_leaf_cert_meta(fullchain_pem)
        except Exception as exc:
            logger.error("failed to parse issued cert for %s: %s", device.cn, exc)
            return _err("internal_error", "Failed to parse issued certificate", 500)

        # ── Persist and audit ─────────────────────────────────────────────────
        certs_db.record_issued_cert(IssuedCert(
            device_fp=device.fingerprint,
            cn=parsed.cn,
            hostnames=parsed.requested_names,
            serial=serial_hex,
            fingerprint=cert_fp,
            csr_hash=parsed.csr_hash,
            issued_at=datetime.now(UTC).isoformat(),
            not_before=not_before,
            not_after=not_after,
            cert_pem=fullchain_pem,
        ))

        audit.record(AuditEntry(
            event=Event.SIGN_ISSUED,
            actor=f"device:{device.cn}",
            outcome="success",
            device_fp=device.fingerprint,
            device_cn=device.cn,
            source_ip=g.source_ip,
            request_id=g.request_id,
            details={"serial": serial_hex, "not_after": not_after},
        ))

        devices_db.touch_last_seen(device.fingerprint, g.source_ip)

        return jsonify({"cert": fullchain_pem})

    return app
