"""Unit tests for tools/admin_cli.py."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from click.testing import CliRunner

from broker.db import CertsDB, Database, DevicesDB, IssuedCert
from tools.admin_cli import cli


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "test.db"))
    d.connect()
    yield d
    d.close()


@pytest.fixture
def db_path(tmp_path) -> str:
    return str(tmp_path / "test.db")


@pytest.fixture
def runner():
    return CliRunner()


def _run(runner: CliRunner, db_path: str, *args: str):
    """Invoke the CLI with --db set to a temp DB."""
    return runner.invoke(cli, ["--db", db_path, *args])


def _provision(db: Database, fp: str = "aabbcc", cn: str = "dev-01.embetrix.works") -> None:
    DevicesDB(db).provision(
        fingerprint=fp,
        cn=cn,
        hostnames=[cn],
        label="test",
        provisioned_by="admin",
    )


def _record_cert(db: Database, fp: str, csr_hash: str, days_left: int = 90) -> None:
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


# ── provision ─────────────────────────────────────────────────────────────────


class TestProvision:
    def test_exits_zero(self, runner, db_path):
        r = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        assert r.exit_code == 0, r.output

    def test_prints_bearer_token(self, runner, db_path):
        r = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        assert "Bearer token:" in r.output

    def test_token_is_64_hex_chars(self, runner, db_path):
        r = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        token_line = [ln for ln in r.output.splitlines() if "Bearer token:" in ln][0]
        token = token_line.split("Bearer token:")[1].strip()
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_token_fingerprint_stored_in_db(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        r = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        token_line = [ln for ln in r.output.splitlines() if "Bearer token:" in ln][0]
        token = token_line.split("Bearer token:")[1].strip()
        fp = hashlib.sha256(token.encode()).hexdigest()
        device = DevicesDB(db).get_by_fingerprint(fp)
        db.close()
        assert device is not None
        assert device.cn == "dev-01.embetrix.works"

    def test_multiple_hostnames(self, runner, db_path):
        r = _run(runner, db_path, "provision", "--cn", "dev-01.example.com",
                 "--hostname", "dev-01.example.com", "--hostname", "alt.example.com")
        assert r.exit_code == 0

    def test_default_hostname_is_cn(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        # Find the device — fingerprint from output
        rows = DevicesDB(db).list_all()
        db.close()
        assert rows[0].hostnames == ["dev-01.embetrix.works"]

    def test_warns_token_shown_once(self, runner, db_path):
        r = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        assert "will not be shown again" in r.output

    def test_two_tokens_are_different(self, runner, db_path):
        r1 = _run(runner, db_path, "provision", "--cn", "dev-01.embetrix.works")
        r2 = _run(runner, db_path, "provision", "--cn", "dev-02.embetrix.works")
        token1 = [ln for ln in r1.output.splitlines() if "Bearer token:" in ln][0].split()[-1]
        token2 = [ln for ln in r2.output.splitlines() if "Bearer token:" in ln][0].split()[-1]
        assert token1 != token2


# ── devices ───────────────────────────────────────────────────────────────────


class TestDevices:
    def test_empty_db(self, runner, db_path):
        # DB is created on first connect via provision; use a fresh one
        db = Database(db_path)
        db.connect()
        db.close()
        r = _run(runner, db_path, "devices")
        assert r.exit_code == 0
        assert "No devices" in r.output

    def test_lists_active_device(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        r = _run(runner, db_path, "devices")
        assert "dev-01.embetrix.works" in r.output
        assert "aabbcc" in r.output

    def test_excludes_revoked_by_default(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        DevicesDB(db).revoke("aabbcc", "admin", "test")
        db.close()
        r = _run(runner, db_path, "devices")
        assert "No devices" in r.output

    def test_includes_revoked_with_flag(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        DevicesDB(db).revoke("aabbcc", "admin", "test")
        db.close()
        r = _run(runner, db_path, "devices", "--all")
        assert "aabbcc" in r.output


# ── revoke ────────────────────────────────────────────────────────────────────


class TestRevoke:
    def test_revokes_device(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        r = _run(runner, db_path, "revoke", "aabbcc")
        assert r.exit_code == 0
        db = Database(db_path)
        db.connect()
        device = DevicesDB(db).get_by_fingerprint("aabbcc")
        db.close()
        assert device is not None
        assert not device.is_active

    def test_already_revoked_message(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        DevicesDB(db).revoke("aabbcc", "admin", "first")
        db.close()
        r = _run(runner, db_path, "revoke", "aabbcc")
        assert "already revoked" in r.output

    def test_revoke_audited(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        _run(runner, db_path, "revoke", "aabbcc")
        db = Database(db_path)
        db.connect()
        rows = db.conn.execute("SELECT event FROM audit_log").fetchall()
        db.close()
        assert any(r["event"] == "device.revoked" for r in rows)


# ── unrevoke ──────────────────────────────────────────────────────────────────


class TestUnrevoke:
    def test_unrevokes_device(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        DevicesDB(db).revoke("aabbcc", "admin", "oops")
        db.close()
        r = _run(runner, db_path, "unrevoke", "aabbcc")
        assert r.exit_code == 0
        db = Database(db_path)
        db.connect()
        device = DevicesDB(db).get_by_fingerprint("aabbcc")
        db.close()
        assert device is not None
        assert device.is_active

    def test_not_revoked_message(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        r = _run(runner, db_path, "unrevoke", "aabbcc")
        assert "not revoked" in r.output


# ── certs ─────────────────────────────────────────────────────────────────────


class TestCerts:
    def test_no_certs(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        r = _run(runner, db_path, "certs", "aabbcc")
        assert "No certificates" in r.output

    def test_lists_cert(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        _record_cert(db, "aabbcc", "h1", days_left=90)
        db.close()
        r = _run(runner, db_path, "certs", "aabbcc")
        assert "h1" in r.output
        assert "valid" in r.output

    def test_shows_expiring_status(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        _record_cert(db, "aabbcc", "h1", days_left=15)
        db.close()
        r = _run(runner, db_path, "certs", "aabbcc")
        assert "expiring" in r.output

    def test_shows_expired_status(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        _record_cert(db, "aabbcc", "h1", days_left=-5)
        db.close()
        r = _run(runner, db_path, "certs", "aabbcc")
        assert "expired" in r.output


# ── audit ─────────────────────────────────────────────────────────────────────


class TestAudit:
    def _seed(self, runner: CliRunner, db_path: str) -> None:
        db = Database(db_path)
        db.connect()
        _provision(db)
        db.close()
        _run(runner, db_path, "revoke", "aabbcc", "--reason", "test")

    def test_no_entries(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        db.close()
        r = _run(runner, db_path, "audit")
        assert "No audit" in r.output

    def test_shows_events_after_revoke(self, runner, db_path):
        self._seed(runner, db_path)
        r = _run(runner, db_path, "audit")
        assert r.exit_code == 0
        assert "device.revoked" in r.output

    def test_filter_by_event(self, runner, db_path):
        self._seed(runner, db_path)
        r = _run(runner, db_path, "audit", "--event", "device.revoked")
        assert "device.revoked" in r.output

    def test_json_output(self, runner, db_path):
        self._seed(runner, db_path)
        r = _run(runner, db_path, "audit", "--json")
        assert r.exit_code == 0
        first_line = r.output.strip().splitlines()[0]
        data = json.loads(first_line)
        assert "event" in data
        assert "ts" in data

    def test_limit_respected(self, runner, db_path):
        db = Database(db_path)
        db.connect()
        _provision(db)
        for i in range(10):
            DevicesDB(db).touch_last_seen("aabbcc", f"10.0.0.{i}")
        db.close()
        r = _run(runner, db_path, "audit", "--limit", "3")
        # 3 data rows + header + separator = 5 lines minimum, but just check count
        data_lines = [ln for ln in r.output.splitlines() if "UTC" in ln]
        assert len(data_lines) <= 3
