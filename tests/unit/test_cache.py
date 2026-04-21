"""Unit tests for broker/cache.py."""

from datetime import datetime, timedelta, timezone

import pytest

from broker.cache import CertCache, EXPIRY_THRESHOLD
from broker.db import CertsDB, Database, DevicesDB, IssuedCert


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def cache(db):
    return CertCache(CertsDB(db))


def _provision(db: Database, fp: str = "aabbcc", cn: str = "dev-01") -> None:
    DevicesDB(db).provision(
        fingerprint=fp,
        cn=f"{cn}.embetrix.works",
        hostnames=[f"{cn}.embetrix.works"],
        label=cn,
        provisioned_by="test",
    )


def _cert(db: Database, fp: str, csr_hash: str, days_left: float) -> IssuedCert:
    now = datetime.now(timezone.utc)
    cert = IssuedCert(
        device_fp=fp,
        cn="dev-01.embetrix.works",
        hostnames=["dev-01.embetrix.works"],
        serial=csr_hash,
        fingerprint=f"certfp-{csr_hash}",
        csr_hash=csr_hash,
        issued_at=now.isoformat(),
        not_before=now.isoformat(),
        not_after=(now + timedelta(days=days_left)).isoformat(),
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
    )
    CertsDB(db).record_issued_cert(cert)
    return cert


# ── CertCache.get ─────────────────────────────────────────────────────────────


class TestCacheGet:
    def test_miss_when_no_cert_exists(self, cache):
        assert cache.get("aabbcc", "nosuchhash") is None

    def test_hit_when_cert_has_plenty_of_time(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=90)
        assert cache.get("aabbcc", "hash1") is not None

    def test_miss_when_cert_expires_exactly_at_threshold(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=30)
        assert cache.get("aabbcc", "hash1") is None

    def test_miss_when_cert_expires_below_threshold(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=29)
        assert cache.get("aabbcc", "hash1") is None

    def test_miss_when_cert_already_expired(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=-1)
        assert cache.get("aabbcc", "hash1") is None

    def test_hit_returns_correct_cert(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=90)
        result = cache.get("aabbcc", "hash1")
        assert result is not None
        assert result.csr_hash == "hash1"

    def test_miss_for_different_csr_hash(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=90)
        assert cache.get("aabbcc", "otherhash") is None

    def test_miss_for_different_device(self, db, cache):
        _provision(db, fp="aabbcc", cn="dev-01")
        _provision(db, fp="ddeeff", cn="dev-02")
        _cert(db, "aabbcc", "hash1", days_left=90)
        assert cache.get("ddeeff", "hash1") is None

    def test_31_days_is_a_hit(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=31)
        assert cache.get("aabbcc", "hash1") is not None


# ── CertCache.get_best ────────────────────────────────────────────────────────


class TestCacheGetBest:
    def test_none_when_no_certs(self, cache):
        assert cache.get_best("aabbcc") is None

    def test_returns_cert_with_longest_validity(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "short", days_left=10)
        _cert(db, "aabbcc", "long", days_left=180)
        best = cache.get_best("aabbcc")
        assert best is not None
        assert best.csr_hash == "long"

    def test_ignores_expired_certs(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "expired", days_left=-5)
        assert cache.get_best("aabbcc") is None


# ── CertCache.is_expiring ─────────────────────────────────────────────────────


class TestIsExpiring:
    def test_true_when_no_cert(self, cache):
        assert cache.is_expiring("aabbcc") is True

    def test_true_when_best_cert_has_30_days(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=30)
        assert cache.is_expiring("aabbcc") is True

    def test_true_when_best_cert_has_29_days(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=29)
        assert cache.is_expiring("aabbcc") is True

    def test_false_when_best_cert_has_31_days(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=31)
        assert cache.is_expiring("aabbcc") is False

    def test_false_when_best_cert_has_90_days(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=90)
        assert cache.is_expiring("aabbcc") is False

    def test_true_when_all_certs_expired(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "hash1", days_left=-1)
        assert cache.is_expiring("aabbcc") is True

    def test_uses_best_cert_not_most_recent(self, db, cache):
        _provision(db)
        _cert(db, "aabbcc", "old_but_long", days_left=90)
        _cert(db, "aabbcc", "new_but_short", days_left=10)
        assert cache.is_expiring("aabbcc") is False
