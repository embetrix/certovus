"""Unit tests for broker/rate_limit.py."""

from datetime import UTC, datetime, timedelta

import pytest

from broker.cache import CertCache
from broker.db import CertsDB, Database, DevicesDB, IssuedCert
from broker.errors import RateLimitError
from broker.rate_limit import RateLimiter


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def certs_db(db):
    return CertsDB(db)


@pytest.fixture
def cache(certs_db):
    return CertCache(certs_db)


def _provision(db: Database, fp: str = "aabbcc", cn: str = "dev-01") -> None:
    DevicesDB(db).provision(
        fingerprint=fp,
        cn=f"{cn}.embetrix.works",
        hostnames=[f"{cn}.embetrix.works"],
        label=cn,
        provisioned_by="test",
    )


def _record_cert(db: Database, fp: str, csr_hash: str, days_left: float = 90) -> None:
    now = datetime.now(UTC)
    CertsDB(db).record_issued_cert(IssuedCert(
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
    ))


def _limiter(certs_db, cache, **overrides) -> RateLimiter:
    defaults = dict(per_device_limit=1, per_device_window_hours=24, global_limit=5, global_window_days=7)
    return RateLimiter(certs_db, cache, **{**defaults, **overrides})


# ── Disabled limits ───────────────────────────────────────────────────────────


class TestDisabledLimits:
    def test_per_device_disabled_allows_many(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=0, global_limit=0)
        for i in range(10):
            _record_cert(db, "aabbcc", f"h{i}")
        limiter.check("aabbcc")  # must not raise

    def test_global_disabled_allows_many(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, global_limit=0, per_device_limit=0)
        for i in range(100):
            _record_cert(db, "aabbcc", f"h{i}")
        limiter.check("aabbcc")  # must not raise

    def test_both_disabled_never_raises(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=0, global_limit=0)
        for i in range(200):
            _record_cert(db, "aabbcc", f"h{i}")
        limiter.check("aabbcc")


# ── Per-device limit ──────────────────────────────────────────────────────────


class TestPerDeviceLimit:
    def test_passes_when_no_prior_certs(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache)
        limiter.check("aabbcc")  # must not raise

    def test_passes_at_limit_minus_one(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=3)
        _record_cert(db, "aabbcc", "h1")
        _record_cert(db, "aabbcc", "h2")
        limiter.check("aabbcc")  # 2 certs, limit is 3 → ok

    def test_raises_at_limit(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=1)
        _record_cert(db, "aabbcc", "h1")
        with pytest.raises(RateLimitError, match="per-device"):
            limiter.check("aabbcc")

    def test_only_counts_within_window(self, db, certs_db, cache):
        _provision(db)
        # Record cert with not_after far in past to simulate old issuance.
        # We can't control issued_at directly, so use a 1-hour window and rely
        # on the cert having been recorded "now" — check with a zero window to force miss.
        limiter = _limiter(certs_db, cache, per_device_limit=1, per_device_window_hours=0)
        _record_cert(db, "aabbcc", "h1")
        limiter.check("aabbcc")  # window is 0 hours → nothing counted → passes

    def test_does_not_count_other_devices(self, db, certs_db, cache):
        _provision(db, fp="aabbcc", cn="dev-01")
        _provision(db, fp="ddeeff", cn="dev-02")
        limiter = _limiter(certs_db, cache, per_device_limit=1)
        _record_cert(db, "ddeeff", "h1")
        limiter.check("aabbcc")  # other device's cert → should not count

    def test_error_message_includes_window_hours(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=1, per_device_window_hours=48)
        _record_cert(db, "aabbcc", "h1")
        with pytest.raises(RateLimitError, match="48 hours"):
            limiter.check("aabbcc")


# ── Per-device bypass when cert is expiring ───────────────────────────────────


class TestExpiryBypass:
    def test_bypass_when_best_cert_is_expiring(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=1)
        _record_cert(db, "aabbcc", "h1", days_left=10)  # expiring → bypass
        limiter.check("aabbcc")  # must not raise per-device

    def test_bypass_when_no_cert_exists(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=1)
        # Record an issued cert for counting but with expiring best cert
        # Simulate: device has issued cert but best is expiring.
        # Easiest: no cert at all → is_expiring=True → bypass
        limiter.check("aabbcc")  # no cert → is_expiring → bypass

    def test_no_bypass_when_cert_is_fresh(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, per_device_limit=1)
        _record_cert(db, "aabbcc", "h1", days_left=90)  # fresh → no bypass
        with pytest.raises(RateLimitError, match="per-device"):
            limiter.check("aabbcc")

    def test_bypass_still_subject_to_global_limit(self, db, certs_db, cache):
        _provision(db, fp="aabbcc", cn="dev-01")
        _provision(db, fp="ddeeff", cn="dev-02")
        limiter = _limiter(certs_db, cache, per_device_limit=1, global_limit=2)
        # Fill global limit
        _record_cert(db, "ddeeff", "g1")
        _record_cert(db, "ddeeff", "g2")
        # aabbcc has expiring cert → per-device bypass, but global still fires
        _record_cert(db, "aabbcc", "h1", days_left=10)
        with pytest.raises(RateLimitError, match="global"):
            limiter.check("aabbcc")


# ── Global limit ──────────────────────────────────────────────────────────────


class TestGlobalLimit:
    def test_passes_when_under_global_limit(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, global_limit=5, per_device_limit=0)
        for i in range(4):
            _record_cert(db, "aabbcc", f"h{i}")
        limiter.check("aabbcc")  # 4 < 5 → ok

    def test_raises_at_global_limit(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, global_limit=3, per_device_limit=0)
        for i in range(3):
            _record_cert(db, "aabbcc", f"h{i}")
        with pytest.raises(RateLimitError, match="global"):
            limiter.check("aabbcc")

    def test_counts_all_devices_globally(self, db, certs_db, cache):
        _provision(db, fp="aabbcc", cn="dev-01")
        _provision(db, fp="ddeeff", cn="dev-02")
        limiter = _limiter(certs_db, cache, global_limit=2, per_device_limit=0)
        _record_cert(db, "aabbcc", "h1")
        _record_cert(db, "ddeeff", "h2")
        with pytest.raises(RateLimitError, match="global"):
            limiter.check("aabbcc")

    def test_error_message_includes_window_days(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, global_limit=1, global_window_days=14, per_device_limit=0)
        _record_cert(db, "aabbcc", "h1")
        with pytest.raises(RateLimitError, match="14 days"):
            limiter.check("aabbcc")

    def test_global_checked_before_per_device(self, db, certs_db, cache):
        _provision(db)
        limiter = _limiter(certs_db, cache, global_limit=1, per_device_limit=1)
        _record_cert(db, "aabbcc", "h1", days_left=90)
        # Both limits would fire — global error message should appear (checked first)
        with pytest.raises(RateLimitError, match="global"):
            limiter.check("aabbcc")
