"""Unit tests for broker/audit.py."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from broker.audit import AuditEntry, AuditLog, Event
from broker.db import Database, DevicesDB


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def audit(db):
    return AuditLog(db)


def _provision(db: Database, fingerprint: str = "aabbcc", cn: str = "dev-01") -> None:
    """Insert a minimal device row so FK constraints pass."""
    DevicesDB(db).provision(
        fingerprint=fingerprint,
        cn=f"{cn}.embetrix.works",
        hostnames=[f"{cn}.embetrix.works"],
        label=cn,
        client_cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        provisioned_by="test",
    )


def _entry(**overrides) -> AuditEntry:
    # device_fp defaults to None so FK constraint never fires unless a device
    # has been explicitly inserted.
    base = dict(
        event=Event.AUTH_SUCCESS,
        actor="system",
        outcome="success",
        source_ip="10.0.0.1",
        request_id="req-abc",
    )
    return AuditEntry(**{**base, **overrides})


# ── Event enum ────────────────────────────────────────────────────────────────


class TestEvent:
    def test_string_values_match_spec(self):
        assert Event.AUTH_SUCCESS.value == "auth.success"
        assert Event.SIGN_ISSUED.value == "sign.issued"
        assert Event.DEVICE_REVOKED.value == "device.revoked"
        assert Event.ADMIN_LOGIN_FAILED.value == "admin.login_failed"

    def test_all_events_have_dot_separator(self):
        for e in Event:
            assert "." in e.value, f"{e.value!r} missing category prefix"

    def test_roundtrip_from_string(self):
        assert Event("sign.cache_hit") is Event.SIGN_CACHE_HIT


# ── AuditLog.record ───────────────────────────────────────────────────────────


class TestRecord:
    def test_record_inserts_row(self, db, audit):
        _provision(db)
        audit.record(_entry(
            actor="device:dev-01.embetrix.works",
            device_fp="aabbcc",
            device_cn="dev-01.embetrix.works",
        ))
        row = db.conn.execute("SELECT * FROM audit_log").fetchone()
        assert row is not None
        assert row["event"] == "auth.success"
        assert row["actor"] == "device:dev-01.embetrix.works"
        assert row["outcome"] == "success"
        assert row["device_fp"] == "aabbcc"
        assert row["source_ip"] == "10.0.0.1"

    def test_record_serialises_details_as_json(self, db, audit):
        audit.record(_entry(details={"serial": "deadbeef", "count": 3}))
        row = db.conn.execute("SELECT details FROM audit_log").fetchone()
        import json
        assert json.loads(row["details"]) == {"serial": "deadbeef", "count": 3}

    def test_record_stores_none_details_as_null(self, db, audit):
        audit.record(_entry(details=None))
        row = db.conn.execute("SELECT details FROM audit_log").fetchone()
        assert row["details"] is None

    def test_record_does_not_raise_on_db_error(self, db, audit):
        """Audit failures must never propagate to callers."""
        db.close()
        # Should silently swallow the OperationalError, not raise
        audit.record(_entry())

    def test_record_logs_error_on_db_failure(self, db, audit):
        db.close()
        with patch("broker.audit.logger") as mock_log:
            audit.record(_entry())
            mock_log.error.assert_called_once()

    def test_record_multiple_entries(self, db, audit):
        for outcome in ("success", "failure", "success"):
            audit.record(_entry(outcome=outcome))
        count = db.conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert count == 3


# ── AuditLog.query ────────────────────────────────────────────────────────────


class TestQuery:
    def _populate(self, db, audit):
        _provision(db, fingerprint="aa", cn="dev-01")
        _provision(db, fingerprint="bb", cn="dev-02")
        audit.record(_entry(event=Event.AUTH_SUCCESS, outcome="success", device_fp="aa", device_cn="dev-01.embetrix.works"))
        audit.record(_entry(event=Event.AUTH_REVOKED, outcome="failure", device_fp="bb", device_cn="dev-02.embetrix.works"))
        audit.record(_entry(event=Event.SIGN_ISSUED, outcome="success", device_fp="aa", device_cn="dev-01.embetrix.works"))

    def test_query_all(self, db, audit):
        self._populate(db, audit)
        assert len(audit.query()) == 3

    def test_query_by_device_fp(self, db, audit):
        self._populate(db, audit)
        rows = audit.query(device_fp="aa")
        assert len(rows) == 2
        assert all(r.device_fp == "aa" for r in rows)

    def test_query_by_device_cn(self, db, audit):
        self._populate(db, audit)
        rows = audit.query(device_cn="dev-02.embetrix.works")
        assert len(rows) == 1
        assert rows[0].event is Event.AUTH_REVOKED

    def test_query_by_event(self, db, audit):
        self._populate(db, audit)
        rows = audit.query(event=Event.SIGN_ISSUED)
        assert len(rows) == 1
        assert rows[0].device_fp == "aa"

    def test_query_by_outcome(self, db, audit):
        self._populate(db, audit)
        rows = audit.query(outcome="failure")
        assert len(rows) == 1
        assert rows[0].event is Event.AUTH_REVOKED

    def test_query_since(self, db, audit):
        self._populate(db, audit)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        rows = audit.query(since=future)
        assert len(rows) == 0

    def test_query_until(self, db, audit):
        self._populate(db, audit)
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        rows = audit.query(until=past)
        assert len(rows) == 0

    def test_query_limit(self, db, audit):
        self._populate(db, audit)
        rows = audit.query(limit=2)
        assert len(rows) == 2

    def test_query_returns_newest_first(self, db, audit):
        self._populate(db, audit)
        rows = audit.query()
        timestamps = [r.ts for r in rows]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_query_deserialises_details(self, audit):
        audit.record(_entry(details={"key": "value"}))
        rows = audit.query()
        assert rows[0].details == {"key": "value"}

    def test_query_empty_db(self, audit):
        assert audit.query() == []
