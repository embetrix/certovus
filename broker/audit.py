"""Append-only audit logger for Certovus.

AuditLog.record() is the single write path for all audit events.  It is
intentionally bullet-proof: any exception during the INSERT is caught and
logged to the application logger so it appears in gunicorn's error stream,
but it never propagates to the caller.  Audit failures must never affect a
device's certificate issuance response.

Usage (inside a Flask handler)::

    audit.record(AuditEntry(
        event=Event.SIGN_ISSUED,
        actor=f"device:{cn}",
        outcome="success",
        device_fp=fp,
        device_cn=cn,
        source_ip=request.remote_addr,
        request_id=g.request_id,
        details={"serial": cert_serial, "hostnames": hostnames},
    ))
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from broker.db import Database

logger = logging.getLogger(__name__)


# ── Event taxonomy ────────────────────────────────────────────────────────────


class Event(StrEnum):
    """Closed set of audit event types.  String values are stored in the DB."""

    # Device lifecycle
    DEVICE_PROVISIONED = "device.provisioned"
    DEVICE_REVOKED     = "device.revoked"
    DEVICE_UNREVOKED   = "device.unrevoked"
    DEVICE_UPDATED     = "device.updated"

    # Authentication
    AUTH_SUCCESS       = "auth.success"
    AUTH_UNKNOWN_TOKEN = "auth.unknown_token"   # token hash not in DB
    AUTH_MISSING_TOKEN = "auth.missing_token"   # no Authorization header
    AUTH_REVOKED       = "auth.revoked"

    # Certificate issuance
    SIGN_REQUESTED      = "sign.requested"
    SIGN_BAD_CSR        = "sign.bad_csr"
    SIGN_HOSTNAME_DENIED = "sign.hostname_denied"
    SIGN_RATE_LIMITED   = "sign.rate_limited"
    SIGN_CACHE_HIT      = "sign.cache_hit"
    SIGN_ACME_FAILED    = "sign.acme_failed"
    SIGN_ISSUED         = "sign.issued"

    # Cert management
    CERT_REVOKED = "cert.revoked"

    # Admin CLI
    ADMIN_LOGIN        = "admin.login"
    ADMIN_LOGIN_FAILED = "admin.login_failed"


# ── AuditEntry ────────────────────────────────────────────────────────────────


@dataclass
class AuditEntry:
    """One row in the audit_log table.

    ts defaults to now (UTC).  Callers only need to supply the fields they know;
    everything else defaults to None / auto-generated.
    """

    event:      Event
    actor:      str          # "device:<cn>" | "admin:<name>" | "system"
    outcome:    str          # "success" | "failure"
    ts:         str          = field(default_factory=lambda: datetime.now(UTC).isoformat())
    device_fp:  str | None              = None
    device_cn:  str | None              = None
    source_ip:  str | None              = None
    user_agent: str | None              = None
    details:    dict[str, Any] | None   = None
    request_id: str | None              = None


# ── AuditLog ──────────────────────────────────────────────────────────────────


class AuditLog:
    """Write and query the audit_log table.

    Shares the same Database connection as DevicesDB / CertsDB.  record() is
    always called outside of any open business transaction so the INSERT is a
    standalone autocommit operation.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, entry: AuditEntry) -> None:
        """Persist one audit entry.  Never raises under any circumstances."""
        try:
            self._db.conn.execute(
                """
                INSERT INTO audit_log
                    (ts, event, device_fp, device_cn, actor,
                     source_ip, user_agent, outcome, details, request_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.ts,
                    entry.event.value,
                    entry.device_fp,
                    entry.device_cn,
                    entry.actor,
                    entry.source_ip,
                    entry.user_agent,
                    entry.outcome,
                    json.dumps(entry.details) if entry.details is not None else None,
                    entry.request_id,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "audit write failed — event=%s actor=%s error=%s",
                entry.event.value,
                entry.actor,
                exc,
            )

    def query(
        self,
        *,
        device_fp:  str | None      = None,
        device_cn:  str | None      = None,
        event:      Event | None    = None,
        since:      datetime | None = None,
        until:      datetime | None = None,
        outcome:    str | None      = None,
        limit:      int                = 100,
    ) -> list[AuditEntry]:
        """Return audit rows matching the given filters, newest first.

        Used by the admin CLI's `certovus audit` subcommand.
        """
        clauses: list[str] = []
        params:  list[Any] = []

        if device_fp is not None:
            clauses.append("device_fp = ?")
            params.append(device_fp)
        if device_cn is not None:
            clauses.append("device_cn = ?")
            params.append(device_cn)
        if event is not None:
            clauses.append("event = ?")
            params.append(event.value)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since.isoformat())
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until.isoformat())
        if outcome is not None:
            clauses.append("outcome = ?")
            params.append(outcome)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        rows = self._db.conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY ts DESC LIMIT ?",  # noqa: S608
            params,
        ).fetchall()

        return [_row_to_entry(r) for r in rows]


# ── Row helper ────────────────────────────────────────────────────────────────


def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
    raw_details = row["details"]
    return AuditEntry(
        ts=row["ts"],
        event=Event(row["event"]),
        device_fp=row["device_fp"],
        device_cn=row["device_cn"],
        actor=row["actor"],
        source_ip=row["source_ip"],
        user_agent=row["user_agent"],
        outcome=row["outcome"],
        details=json.loads(raw_details) if raw_details is not None else None,
        request_id=row["request_id"],
    )
