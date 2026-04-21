"""Unit tests for broker/db.py — in-memory SQLite, no mocks."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from broker.db import CertsDB, Database, Device, DevicesDB, IssuedCert


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def devices(db):
    return DevicesDB(db)


@pytest.fixture
def certs(db):
    return CertsDB(db)


def _sample_device(**overrides) -> dict:
    base = dict(
        fingerprint="aabbcc",
        cn="dev-01.embetrix.works",
        hostnames=["dev-01.embetrix.works"],
        label="Test device",
        provisioned_by="admin",
    )
    return {**base, **overrides}


def _sample_cert(device_fp: str, **overrides) -> IssuedCert:
    now = datetime.now(timezone.utc)
    base = dict(
        device_fp=device_fp,
        cn="dev-01.embetrix.works",
        hostnames=["dev-01.embetrix.works"],
        serial="deadbeef",
        fingerprint="certfp",
        csr_hash="csrhash",
        issued_at=now.isoformat(),
        not_before=now.isoformat(),
        not_after=(now + timedelta(days=90)).isoformat(),
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
    )
    return IssuedCert(**{**base, **overrides})


# ── DevicesDB ─────────────────────────────────────────────────────────────────


class TestDevicesDB:
    def test_provision_and_get_by_fingerprint(self, devices):
        devices.provision(**_sample_device())
        d = devices.get_by_fingerprint("aabbcc")
        assert d is not None
        assert d.cn == "dev-01.embetrix.works"
        assert d.hostnames == ["dev-01.embetrix.works"]
        assert d.is_active

    def test_get_by_cn(self, devices):
        devices.provision(**_sample_device())
        d = devices.get_by_cn("dev-01.embetrix.works")
        assert d is not None
        assert d.fingerprint == "aabbcc"

    def test_get_by_fingerprint_missing(self, devices):
        assert devices.get_by_fingerprint("nonexistent") is None

    def test_duplicate_fingerprint_raises(self, devices):
        devices.provision(**_sample_device())
        with pytest.raises(sqlite3.IntegrityError):
            devices.provision(**_sample_device())

    def test_duplicate_cn_raises(self, devices):
        devices.provision(**_sample_device())
        with pytest.raises(sqlite3.IntegrityError):
            devices.provision(**_sample_device(fingerprint="different"))

    def test_list_all_excludes_revoked_by_default(self, devices):
        devices.provision(**_sample_device())
        devices.provision(**_sample_device(fingerprint="dd", cn="dev-02.embetrix.works"))
        devices.revoke("dd", "admin", "test")
        active = devices.list_all()
        assert len(active) == 1
        assert active[0].fingerprint == "aabbcc"

    def test_list_all_includes_revoked_when_requested(self, devices):
        devices.provision(**_sample_device())
        devices.provision(**_sample_device(fingerprint="dd", cn="dev-02.embetrix.works"))
        devices.revoke("dd", "admin", "test")
        all_devices = devices.list_all(include_revoked=True)
        assert len(all_devices) == 2

    def test_revoke(self, devices):
        devices.provision(**_sample_device())
        result = devices.revoke("aabbcc", "admin", "compromised")
        assert result is True
        d = devices.get_by_fingerprint("aabbcc")
        assert d is not None
        assert not d.is_active
        assert d.revoked_by == "admin"
        assert d.revoked_reason == "compromised"

    def test_revoke_already_revoked_returns_false(self, devices):
        devices.provision(**_sample_device())
        devices.revoke("aabbcc", "admin", "first")
        assert devices.revoke("aabbcc", "admin", "second") is False

    def test_unrevoke(self, devices):
        devices.provision(**_sample_device())
        devices.revoke("aabbcc", "admin", "oops")
        assert devices.unrevoke("aabbcc") is True
        d = devices.get_by_fingerprint("aabbcc")
        assert d is not None
        assert d.is_active
        assert d.revoked_at is None

    def test_unrevoke_active_device_returns_false(self, devices):
        devices.provision(**_sample_device())
        assert devices.unrevoke("aabbcc") is False

    def test_touch_last_seen(self, devices):
        devices.provision(**_sample_device())
        devices.touch_last_seen("aabbcc", "1.2.3.4")
        d = devices.get_by_fingerprint("aabbcc")
        assert d is not None
        assert d.last_seen_ip == "1.2.3.4"
        assert d.last_seen_at is not None


# ── CertsDB ───────────────────────────────────────────────────────────────────


class TestCertsDB:
    def test_record_and_get_by_csr_hash(self, devices, certs):
        devices.provision(**_sample_device())
        cert = _sample_cert("aabbcc")
        row_id = certs.record_issued_cert(cert)
        assert isinstance(row_id, int)
        found = certs.get_by_csr_hash("aabbcc", "csrhash")
        assert found is not None
        assert found.serial == "deadbeef"

    def test_get_valid_certs_excludes_expired(self, devices, certs):
        devices.provision(**_sample_device())
        now = datetime.now(timezone.utc)
        expired = _sample_cert(
            "aabbcc",
            csr_hash="old",
            not_after=(now - timedelta(days=1)).isoformat(),
        )
        valid = _sample_cert("aabbcc", csr_hash="new")
        certs.record_issued_cert(expired)
        certs.record_issued_cert(valid)
        result = certs.get_valid_certs("aabbcc")
        assert len(result) == 1
        assert result[0].csr_hash == "new"

    def test_get_best_cert(self, devices, certs):
        devices.provision(**_sample_device())
        now = datetime.now(timezone.utc)
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h1"))
        certs.record_issued_cert(
            _sample_cert(
                "aabbcc",
                csr_hash="h2",
                not_after=(now + timedelta(days=180)).isoformat(),
            )
        )
        best = certs.get_best_cert("aabbcc")
        assert best is not None
        assert best.csr_hash == "h2"

    def test_count_issued_since(self, devices, certs):
        devices.provision(**_sample_device())
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h1"))
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h2"))
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        assert certs.count_issued_since(since) == 2

    def test_count_issued_since_for_device(self, devices, certs):
        devices.provision(**_sample_device())
        devices.provision(**_sample_device(fingerprint="dd", cn="dev-02.embetrix.works"))
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h1"))
        certs.record_issued_cert(_sample_cert("dd", csr_hash="h2"))
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        assert certs.count_issued_since_for_device("aabbcc", since) == 1

    def test_list_for_device(self, devices, certs):
        devices.provision(**_sample_device())
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h1"))
        certs.record_issued_cert(_sample_cert("aabbcc", csr_hash="h2"))
        result = certs.list_for_device("aabbcc")
        assert len(result) == 2
