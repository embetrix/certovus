"""Unit tests for broker/app.py."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from broker.app import create_app
from broker.audit import AuditLog
from broker.cache import CertCache
from broker.db import CertsDB, Database, DevicesDB
from broker.errors import ACMEError
from broker.rate_limit import RateLimiter

# ── Crypto helpers ────────────────────────────────────────────────────────────


def _make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _make_csr(key: ec.EllipticCurvePrivateKey, cn: str, sans: list[str] | None = None) -> str:
    builder = (
        crypto_x509.CertificateSigningRequestBuilder()
        .subject_name(crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    )
    if sans:
        builder = builder.add_extension(
            crypto_x509.SubjectAlternativeName([crypto_x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.PEM).decode()


def _make_cert_pem(cn: str, days: int = 90) -> str:
    key = _make_key()
    now = datetime.now(UTC)
    name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode()


def _fp(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── Fixtures ──────────────────────────────────────────────────────────────────


TOKEN = "supersecrettoken"
DEVICE_FP = _fp(TOKEN)
DEVICE_CN = "dev-01.embetrix.works"
DEVICE_HOSTNAME = "dev-01.embetrix.works"


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def devices_db(db):
    return DevicesDB(db)


@pytest.fixture
def certs_db(db):
    return CertsDB(db)


@pytest.fixture
def audit(db):
    return AuditLog(db)


@pytest.fixture
def cache(certs_db):
    return CertCache(certs_db)


@pytest.fixture
def rate_limiter(certs_db, cache):
    return RateLimiter(certs_db, cache, per_device_limit=0, global_limit=0)


@pytest.fixture
def acme_mock():
    m = MagicMock()
    m.issue.return_value = _make_cert_pem(DEVICE_CN)
    return m


@pytest.fixture
def dns_mock():
    return MagicMock()


@pytest.fixture
def app(devices_db, certs_db, audit, cache, rate_limiter, acme_mock, dns_mock):
    devices_db.provision(
        fingerprint=DEVICE_FP,
        cn=DEVICE_CN,
        hostnames=[DEVICE_HOSTNAME],
        label="test-device",
        provisioned_by="test",
    )
    return create_app(
        acme_client=acme_mock,
        dns_provider=dns_mock,
        rate_limiter=rate_limiter,
        cache=cache,
        audit=audit,
        devices_db=devices_db,
        certs_db=certs_db,
    )


@pytest.fixture
def client(app):
    app.config["TESTING"] = True
    return app.test_client()


def _auth_headers(token: str = TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _csr_body(cn: str = DEVICE_CN) -> dict:
    key = _make_key()
    return {"csr": _make_csr(key, cn, sans=[cn])}


# ── Health ────────────────────────────────────────────────────────────────────


class TestHealth:
    def test_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_returns_ok_status(self, client):
        resp = client.get("/health")
        assert resp.get_json() == {"status": "ok"}

    def test_no_auth_required(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200


# ── Auth ──────────────────────────────────────────────────────────────────────


class TestAuth:
    def test_missing_auth_header_returns_401(self, client):
        resp = client.post("/sign", json=_csr_body())
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "missing_token"

    def test_non_bearer_scheme_returns_401(self, client):
        resp = client.post("/sign", headers={"Authorization": "Basic abc"}, json=_csr_body())
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "missing_token"

    def test_unknown_token_returns_401(self, client):
        resp = client.post("/sign", headers=_auth_headers("wrongtoken"), json=_csr_body())
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unknown_token"

    def test_revoked_device_returns_403(self, client, devices_db):
        devices_db.revoke(DEVICE_FP, "admin", "compromised")
        resp = client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "device_revoked"

    def test_valid_token_proceeds(self, client):
        resp = client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert resp.status_code != 401
        assert resp.status_code != 403


# ── Request body validation ───────────────────────────────────────────────────


class TestRequestBody:
    def test_missing_body_returns_400(self, client):
        resp = client.post("/sign", headers=_auth_headers())
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_request"

    def test_missing_csr_field_returns_400(self, client):
        resp = client.post("/sign", headers=_auth_headers(), json={"other": "field"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_request"

    def test_invalid_csr_returns_400(self, client):
        resp = client.post("/sign", headers=_auth_headers(), json={"csr": "notacsr"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "invalid_csr"

    def test_hostname_not_allowed_returns_403(self, client):
        key = _make_key()
        csr = _make_csr(key, "other.example.com", sans=["other.example.com"])
        resp = client.post("/sign", headers=_auth_headers(), json={"csr": csr})
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "hostname_denied"


# ── Cache hit ─────────────────────────────────────────────────────────────────


class TestCacheHit:
    def test_cache_hit_returns_cached_cert(self, client, db, certs_db, acme_mock):
        key = _make_key()
        csr_pem = _make_csr(key, DEVICE_CN, sans=[DEVICE_CN])
        # First request issues via ACME
        resp1 = client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        assert resp1.status_code == 200

        # Second request with same CSR should hit cache
        resp2 = client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        assert resp2.status_code == 200
        # ACME was only called once
        assert acme_mock.issue.call_count == 1

    def test_cache_hit_returns_same_cert(self, client, acme_mock):
        key = _make_key()
        csr_pem = _make_csr(key, DEVICE_CN, sans=[DEVICE_CN])
        resp1 = client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        resp2 = client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        assert resp1.get_json()["cert"] == resp2.get_json()["cert"]


# ── Rate limit ────────────────────────────────────────────────────────────────


class TestRateLimit:
    def test_rate_limited_returns_429(self, app, devices_db, certs_db, cache, audit, acme_mock, dns_mock):
        strict_limiter = RateLimiter(certs_db, cache, per_device_limit=1, global_limit=0)
        strict_app = create_app(
            acme_client=acme_mock,
            dns_provider=dns_mock,
            rate_limiter=strict_limiter,
            cache=cache,
            audit=audit,
            devices_db=devices_db,
            certs_db=certs_db,
        )
        strict_app.config["TESTING"] = True
        c = strict_app.test_client()

        key1 = _make_key()
        key2 = _make_key()
        csr1 = _make_csr(key1, DEVICE_CN, sans=[DEVICE_CN])
        csr2 = _make_csr(key2, DEVICE_CN, sans=[DEVICE_CN])

        resp1 = c.post("/sign", headers=_auth_headers(), json={"csr": csr1})
        assert resp1.status_code == 200

        resp2 = c.post("/sign", headers=_auth_headers(), json={"csr": csr2})
        assert resp2.status_code == 429
        assert resp2.get_json()["error"] == "rate_limited"


# ── Successful issuance ───────────────────────────────────────────────────────


class TestIssuance:
    def test_returns_200_with_cert(self, client):
        resp = client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert resp.status_code == 200
        data = resp.get_json()
        assert "cert" in data
        assert "BEGIN CERTIFICATE" in data["cert"]

    def test_calls_acme_issue(self, client, acme_mock):
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        acme_mock.issue.assert_called_once()

    def test_cert_recorded_in_db(self, client, certs_db):
        key = _make_key()
        csr_pem = _make_csr(key, DEVICE_CN, sans=[DEVICE_CN])
        client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        certs = certs_db.list_for_device(DEVICE_FP)
        assert len(certs) == 1

    def test_touch_last_seen_called(self, client, devices_db):
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        device = devices_db.get_by_fingerprint(DEVICE_FP)
        assert device.last_seen_at is not None

    def test_acme_error_returns_502(self, client, acme_mock):
        acme_mock.issue.side_effect = ACMEError("DNS timeout")
        resp = client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert resp.status_code == 502
        assert resp.get_json()["error"] == "acme_error"

    def test_unexpected_error_returns_500(self, client, acme_mock):
        acme_mock.issue.side_effect = RuntimeError("something broke")
        resp = client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert resp.status_code == 500
        assert resp.get_json()["error"] == "internal_error"


# ── Audit ─────────────────────────────────────────────────────────────────────


class TestAudit:
    def _audit_events(self, db) -> list[str]:
        return [row["event"] for row in db.conn.execute("SELECT event FROM audit_log ORDER BY rowid").fetchall()]

    def test_missing_token_audited(self, client, db):
        client.post("/sign", json=_csr_body())
        assert "auth.missing_token" in self._audit_events(db)

    def test_unknown_token_audited(self, client, db):
        client.post("/sign", headers=_auth_headers("wrong"), json=_csr_body())
        assert "auth.unknown_token" in self._audit_events(db)

    def test_revoked_device_audited(self, client, db, devices_db):
        devices_db.revoke(DEVICE_FP, "admin", "test")
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert "auth.revoked" in self._audit_events(db)

    def test_auth_success_audited(self, client, db):
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert "auth.success" in self._audit_events(db)

    def test_sign_issued_audited(self, client, db):
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert "sign.issued" in self._audit_events(db)

    def test_cache_hit_audited(self, client, db):
        key = _make_key()
        csr_pem = _make_csr(key, DEVICE_CN, sans=[DEVICE_CN])
        client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        client.post("/sign", headers=_auth_headers(), json={"csr": csr_pem})
        assert "sign.cache_hit" in self._audit_events(db)

    def test_bad_csr_audited(self, client, db):
        client.post("/sign", headers=_auth_headers(), json={"csr": "garbage"})
        assert "sign.bad_csr" in self._audit_events(db)

    def test_hostname_denied_audited(self, client, db):
        key = _make_key()
        csr = _make_csr(key, "other.example.com", sans=["other.example.com"])
        client.post("/sign", headers=_auth_headers(), json={"csr": csr})
        assert "sign.hostname_denied" in self._audit_events(db)

    def test_acme_failed_audited(self, client, db, acme_mock):
        acme_mock.issue.side_effect = ACMEError("timeout")
        client.post("/sign", headers=_auth_headers(), json=_csr_body())
        assert "sign.acme_failed" in self._audit_events(db)
