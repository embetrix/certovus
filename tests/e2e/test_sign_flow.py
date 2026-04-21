"""End-to-end tests for the full certificate issuance flow.

Requires the pebble and challtestsrv services to be reachable.
Run inside Docker with: make e2e

pebble is configured with PEBBLE_VA_ALWAYS_VALID=1, so DNS records
don't need to actually resolve — MockDNS still calls challtestsrv to
exercise the full TXT set/delete path, but pebble skips the real lookup.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import UTC

import pytest
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from broker.acme_client import ACMEClient
from broker.app import create_app
from broker.audit import AuditLog
from broker.cache import CertCache
from broker.db import CertsDB, Database, DevicesDB
from broker.dns.noop import NoopDNS
from broker.rate_limit import RateLimiter

PEBBLE_URL = os.environ.get("PEBBLE_URL", "https://pebble:14000/dir")

DEVICE_CN = "e2e-device.example.com"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_csr(cn: str) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        crypto_x509.CertificateSigningRequestBuilder()
        .subject_name(crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .add_extension(
            crypto_x509.SubjectAlternativeName([crypto_x509.DNSName(cn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.PEM)
        .decode()
    )
    return csr, key


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def _db(tmp_path_factory):
    path = tmp_path_factory.mktemp("e2e") / "e2e.db"
    d = Database(str(path))
    d.connect()
    yield d
    d.close()


@pytest.fixture(scope="module")
def _acme_key_path(tmp_path_factory):
    return str(tmp_path_factory.mktemp("acme") / "account.key")


@pytest.fixture(scope="module")
def token():
    return secrets.token_hex(32)


@pytest.fixture(scope="module")
def device_fp(token):
    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture(scope="module")
def app(_db, _acme_key_path, device_fp):
    DevicesDB(_db).provision(
        fingerprint=device_fp,
        cn=DEVICE_CN,
        hostnames=[DEVICE_CN],
        label="e2e test device",
        provisioned_by="e2e",
    )

    acme_client = ACMEClient(
        directory_url=PEBBLE_URL,
        account_key_path=_acme_key_path,
        verify_ssl=False,
    )
    dns_provider = NoopDNS()
    certs_db = CertsDB(_db)
    cache = CertCache(certs_db)
    rate_limiter = RateLimiter(certs_db, cache, per_device_limit=0, global_limit=0)

    flask_app = create_app(
        acme_client=acme_client,
        dns_provider=dns_provider,
        rate_limiter=rate_limiter,
        cache=cache,
        audit=AuditLog(_db),
        devices_db=DevicesDB(_db),
        certs_db=certs_db,
    )
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def issued(client, token, _db, device_fp):
    """Issue one real certificate from pebble and return (resp, csr_pem)."""
    csr, _ = _make_csr(DEVICE_CN)
    resp = client.post("/sign", headers=_auth(token), json={"csr": csr})
    assert resp.status_code == 200, f"ACME issuance failed: {resp.get_json()}"
    return resp, csr


class TestFullIssuance:
    def test_health_reachable(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "ok"}

    def test_sign_returns_200(self, issued):
        resp, _ = issued
        assert resp.status_code == 200

    def test_sign_returns_pem_certificate(self, issued):
        resp, _ = issued
        assert "-----BEGIN CERTIFICATE-----" in resp.get_json()["cert"]

    def test_issued_cert_covers_device_domain(self, issued):
        from cryptography.x509 import DNSName, SubjectAlternativeName, load_pem_x509_certificate
        resp, _ = issued
        cert = load_pem_x509_certificate(resp.get_json()["cert"].encode())
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(DNSName)
        assert DEVICE_CN in dns_names

    def test_cert_recorded_in_db(self, issued, _db, device_fp):
        certs = CertsDB(_db).list_for_device(device_fp)
        assert len(certs) >= 1

    def test_sign_issued_in_audit_log(self, issued, _db):
        rows = _db.conn.execute(
            "SELECT 1 FROM audit_log WHERE event = 'sign.issued' LIMIT 1"
        ).fetchone()
        assert rows is not None


class TestCacheHit:
    def test_same_csr_twice_both_succeed(self, client, token):
        """Two requests with the same CSR must both return 200."""
        csr, _ = _make_csr(DEVICE_CN)
        resp1 = client.post("/sign", headers=_auth(token), json={"csr": csr})
        resp2 = client.post("/sign", headers=_auth(token), json={"csr": csr})
        assert resp1.status_code == 200
        assert resp2.status_code == 200

    def test_cache_hit_when_fresh_cert_in_db(self, client, token, _db, device_fp):
        """Seed a long-lived cert in DB; second request must return it from cache."""
        from datetime import datetime, timedelta

        from broker.csr import parse_csr
        from broker.db import CertsDB, IssuedCert

        csr, _ = _make_csr(DEVICE_CN)
        parsed = parse_csr(csr)
        now = datetime.now(UTC)
        # Insert a cert with 90 days validity directly so cache threshold is met
        CertsDB(_db).record_issued_cert(IssuedCert(
            device_fp=device_fp,
            cn=DEVICE_CN,
            hostnames=[DEVICE_CN],
            serial="cafebabe",
            fingerprint="cachedcertfp",
            csr_hash=parsed.csr_hash,
            issued_at=now.isoformat(),
            not_before=now.isoformat(),
            not_after=(now + timedelta(days=90)).isoformat(),
            cert_pem="-----BEGIN CERTIFICATE-----\ncached\n-----END CERTIFICATE-----",
        ))
        resp = client.post("/sign", headers=_auth(token), json={"csr": csr})
        assert resp.status_code == 200
        # Must have been served from cache (audit event)
        row = _db.conn.execute(
            "SELECT 1 FROM audit_log WHERE event = 'sign.cache_hit' ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        assert row is not None


class TestAuthErrors:
    def test_no_token_rejected(self, client):
        csr, _ = _make_csr(DEVICE_CN)
        resp = client.post("/sign", json={"csr": csr})
        assert resp.status_code == 401

    def test_wrong_token_rejected(self, client):
        csr, _ = _make_csr(DEVICE_CN)
        resp = client.post("/sign", headers=_auth("wrongtoken"), json={"csr": csr})
        assert resp.status_code == 401

    def test_revoked_device_rejected(self, app, token, _db, device_fp):
        DevicesDB(_db).revoke(device_fp, "e2e", "test revocation")
        c = app.test_client()
        csr, _ = _make_csr(DEVICE_CN)
        resp = c.post("/sign", headers=_auth(token), json={"csr": csr})
        assert resp.status_code == 403
        # Restore for subsequent tests
        DevicesDB(_db).unrevoke(device_fp)
