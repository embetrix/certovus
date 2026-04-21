"""SQLite connection manager and DAOs for Certovus.

DevicesDB and CertsDB are thin wrappers around three tables defined in
migrations/001_init.sql.  All timestamps are UTC ISO 8601 strings.  JSON
columns (hostnames) are serialised/deserialised transparently by the DAO layer
so callers always work with plain Python lists.

A single Database instance is shared across all DAOs within one gunicorn worker
process.  WAL mode lets readers proceed without blocking the writer, which is
the dominant access pattern (many auth reads, occasional cert issuances).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

_MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class Device:
    fingerprint: str        # SHA-256(bearer_token) hex
    cn: str
    hostnames: list[str]
    label: str
    provisioned_at: str
    provisioned_by: str
    client_cert_pem: Optional[str] = None  # reserved; nullable
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None
    revoked_reason: Optional[str] = None
    notes: Optional[str] = None
    last_seen_at: Optional[str] = None
    last_seen_ip: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


@dataclass
class IssuedCert:
    device_fp: str
    cn: str
    hostnames: list[str]
    serial: str
    fingerprint: str
    csr_hash: str
    issued_at: str
    not_before: str
    not_after: str
    cert_pem: str
    acme_order_url: Optional[str] = None
    id: Optional[int] = None


# ── Database connection manager ───────────────────────────────────────────────


class Database:
    """Owns the SQLite connection, applies WAL mode, and runs migrations.

    One instance per gunicorn worker process.  Not thread-safe; each worker
    is single-threaded (sync worker type).
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        self._conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; transactions managed explicitly
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._run_migrations()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database.connect() has not been called")
        return self._conn

    @contextmanager
    def transaction(self) -> Generator[None, None, None]:
        """Explicit BEGIN/COMMIT/ROLLBACK block for multi-statement writes."""
        self.conn.execute("BEGIN")
        try:
            yield
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def _run_migrations(self) -> None:
        # _migrations tracking table is created via executescript (DDL, auto-committed).
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS _migrations (
                name       TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        applied = {row[0] for row in self.conn.execute("SELECT name FROM _migrations")}
        for sql_file in sorted(_MIGRATIONS_DIR.glob("*.sql")):
            if sql_file.name not in applied:
                # executescript auto-commits; DDL is idempotent (IF NOT EXISTS)
                self.conn.executescript(sql_file.read_text())
                self.conn.execute(
                    "INSERT INTO _migrations (name, applied_at) VALUES (?, ?)",
                    (sql_file.name, _utcnow()),
                )


# ── Row helpers ───────────────────────────────────────────────────────────────


def _row_to_device(row: sqlite3.Row) -> Device:
    return Device(
        fingerprint=row["fingerprint"],
        cn=row["cn"],
        hostnames=json.loads(row["hostnames"]),
        label=row["label"],
        client_cert_pem=row["client_cert_pem"],  # may be None
        provisioned_at=row["provisioned_at"],
        provisioned_by=row["provisioned_by"],
        revoked_at=row["revoked_at"],
        revoked_by=row["revoked_by"],
        revoked_reason=row["revoked_reason"],
        notes=row["notes"],
        last_seen_at=row["last_seen_at"],
        last_seen_ip=row["last_seen_ip"],
    )


def _row_to_cert(row: sqlite3.Row) -> IssuedCert:
    return IssuedCert(
        id=row["id"],
        device_fp=row["device_fp"],
        cn=row["cn"],
        hostnames=json.loads(row["hostnames"]),
        serial=row["serial"],
        fingerprint=row["fingerprint"],
        csr_hash=row["csr_hash"],
        issued_at=row["issued_at"],
        not_before=row["not_before"],
        not_after=row["not_after"],
        cert_pem=row["cert_pem"],
        acme_order_url=row["acme_order_url"],
    )


# ── DevicesDB ─────────────────────────────────────────────────────────────────


class DevicesDB:
    """DAO for the devices table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get_by_fingerprint(self, fingerprint: str) -> Optional[Device]:
        row = self._db.conn.execute(
            "SELECT * FROM devices WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _row_to_device(row) if row else None

    def get_by_cn(self, cn: str) -> Optional[Device]:
        row = self._db.conn.execute(
            "SELECT * FROM devices WHERE cn = ? ORDER BY provisioned_at DESC LIMIT 1",
            (cn,),
        ).fetchone()
        return _row_to_device(row) if row else None

    def list_all(self, include_revoked: bool = False) -> list[Device]:
        if include_revoked:
            rows = self._db.conn.execute(
                "SELECT * FROM devices ORDER BY provisioned_at DESC"
            ).fetchall()
        else:
            rows = self._db.conn.execute(
                "SELECT * FROM devices WHERE revoked_at IS NULL ORDER BY provisioned_at DESC"
            ).fetchall()
        return [_row_to_device(r) for r in rows]

    def provision(
        self,
        fingerprint: str,
        cn: str,
        hostnames: list[str],
        label: str,
        provisioned_by: str,
        notes: Optional[str] = None,
    ) -> None:
        """Register a new device. Raises sqlite3.IntegrityError on duplicate fingerprint or CN.

        fingerprint must be SHA-256(bearer_token) hex, computed by the caller.
        """
        with self._db.transaction():
            self._db.conn.execute(
                """
                INSERT INTO devices
                    (fingerprint, cn, hostnames, label,
                     provisioned_at, provisioned_by, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    cn,
                    json.dumps(hostnames),
                    label,
                    _utcnow(),
                    provisioned_by,
                    notes,
                ),
            )

    def revoke(self, fingerprint: str, revoked_by: str, reason: str) -> bool:
        """Mark a device revoked. Returns False if already revoked or not found."""
        cur = self._db.conn.execute(
            """
            UPDATE devices
               SET revoked_at = ?, revoked_by = ?, revoked_reason = ?
             WHERE fingerprint = ? AND revoked_at IS NULL
            """,
            (_utcnow(), revoked_by, reason, fingerprint),
        )
        return cur.rowcount == 1

    def unrevoke(self, fingerprint: str) -> bool:
        """Clear revocation. Returns False if not found or not currently revoked."""
        cur = self._db.conn.execute(
            """
            UPDATE devices
               SET revoked_at = NULL, revoked_by = NULL, revoked_reason = NULL
             WHERE fingerprint = ? AND revoked_at IS NOT NULL
            """,
            (fingerprint,),
        )
        return cur.rowcount == 1

    def touch_last_seen(self, fingerprint: str, ip: str) -> None:
        """Update last_seen_at / last_seen_ip. Called on every successful auth."""
        self._db.conn.execute(
            "UPDATE devices SET last_seen_at = ?, last_seen_ip = ? WHERE fingerprint = ?",
            (_utcnow(), ip, fingerprint),
        )

    def update_notes(self, fingerprint: str, notes: str) -> None:
        self._db.conn.execute(
            "UPDATE devices SET notes = ? WHERE fingerprint = ?",
            (notes, fingerprint),
        )


# ── CertsDB ───────────────────────────────────────────────────────────────────


class CertsDB:
    """DAO for the issued_certs table."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def record_issued_cert(self, cert: IssuedCert) -> int:
        """Persist a newly-issued cert and return its row id."""
        row_id: int
        with self._db.transaction():
            cur = self._db.conn.execute(
                """
                INSERT INTO issued_certs
                    (device_fp, cn, hostnames, serial, fingerprint, csr_hash,
                     issued_at, not_before, not_after, acme_order_url, cert_pem)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert.device_fp,
                    cert.cn,
                    json.dumps(cert.hostnames),
                    cert.serial,
                    cert.fingerprint,
                    cert.csr_hash,
                    cert.issued_at,
                    cert.not_before,
                    cert.not_after,
                    cert.acme_order_url,
                    cert.cert_pem,
                ),
            )
            row_id = cur.lastrowid  # type: ignore[assignment]
        return row_id

    def get_by_csr_hash(self, device_fp: str, csr_hash: str) -> Optional[IssuedCert]:
        """Look up an existing issuance by CSR hash — entry point for the cache layer."""
        row = self._db.conn.execute(
            """
            SELECT * FROM issued_certs
             WHERE device_fp = ? AND csr_hash = ?
             ORDER BY issued_at DESC
             LIMIT 1
            """,
            (device_fp, csr_hash),
        ).fetchone()
        return _row_to_cert(row) if row else None

    def get_valid_certs(self, device_fp: str) -> list[IssuedCert]:
        """All non-expired certs for a device, newest first."""
        rows = self._db.conn.execute(
            """
            SELECT * FROM issued_certs
             WHERE device_fp = ? AND not_after > ?
             ORDER BY issued_at DESC
            """,
            (device_fp, _utcnow()),
        ).fetchall()
        return [_row_to_cert(r) for r in rows]

    def get_best_cert(self, device_fp: str) -> Optional[IssuedCert]:
        """The valid cert with the most time remaining — used by the rate-limit bypass check."""
        row = self._db.conn.execute(
            """
            SELECT * FROM issued_certs
             WHERE device_fp = ? AND not_after > ?
             ORDER BY not_after DESC
             LIMIT 1
            """,
            (device_fp, _utcnow()),
        ).fetchone()
        return _row_to_cert(row) if row else None

    def count_issued_since(self, since: datetime) -> int:
        """Global rolling-window issuance count for the LE rate-limit guard."""
        row = self._db.conn.execute(
            "SELECT COUNT(*) FROM issued_certs WHERE issued_at > ?",
            (since.isoformat(),),
        ).fetchone()
        return int(row[0])

    def count_issued_since_for_device(self, device_fp: str, since: datetime) -> int:
        """Per-device issuance count over a rolling window."""
        row = self._db.conn.execute(
            "SELECT COUNT(*) FROM issued_certs WHERE device_fp = ? AND issued_at > ?",
            (device_fp, since.isoformat()),
        ).fetchone()
        return int(row[0])

    def list_for_device(self, device_fp: str, limit: int = 20) -> list[IssuedCert]:
        rows = self._db.conn.execute(
            """
            SELECT * FROM issued_certs
             WHERE device_fp = ?
             ORDER BY issued_at DESC
             LIMIT ?
            """,
            (device_fp, limit),
        ).fetchall()
        return [_row_to_cert(r) for r in rows]
