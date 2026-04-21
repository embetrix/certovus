"""Certovus admin CLI.

Usage
-----
certovus --db /data/certovus.db provision --cn dev-01.embetrix.works \\
    --hostname dev-01.embetrix.works --label "Sensor 01" --by admin

certovus devices [--all]
certovus revoke   FINGERPRINT [--reason TEXT]
certovus unrevoke FINGERPRINT
certovus certs    FINGERPRINT
certovus audit    [--device FP] [--event EVENT] [--outcome TEXT] [--limit N]
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone

import click

from broker.audit import AuditEntry, AuditLog, Event
from broker.db import CertsDB, Database, DevicesDB


# ── Shared options ─────────────────────────────────────────────────────────────


def _default_db() -> str:
    return os.environ.get("BROKER_DB_PATH", "/data/certovus.db")


@click.group()
@click.option("--db", default=_default_db, show_default=True, help="Path to SQLite database.")
@click.pass_context
def cli(ctx: click.Context, db: str) -> None:
    """Certovus certificate broker — admin CLI."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db


def _open_db(ctx: click.Context) -> Database:
    path = ctx.obj["db_path"]
    d = Database(path)
    d.connect()
    return d


# ── provision ─────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--cn", required=True, help="Device common name (FQDN).")
@click.option("--hostname", "hostnames", multiple=True, help="Allowed hostname (repeat for multiple). Defaults to --cn.")
@click.option("--label", default="", help="Human-readable label.")
@click.option("--by", "provisioned_by", default="admin", show_default=True, help="Who is provisioning this device.")
@click.pass_context
def provision(ctx: click.Context, cn: str, hostnames: tuple[str, ...], label: str, provisioned_by: str) -> None:
    """Provision a new device and print its bearer token.

    The token is shown exactly once — save it immediately.
    """
    if not hostnames:
        hostnames = (cn,)

    token = secrets.token_hex(32)
    fingerprint = hashlib.sha256(token.encode()).hexdigest()

    db = _open_db(ctx)
    try:
        DevicesDB(db).provision(
            fingerprint=fingerprint,
            cn=cn,
            hostnames=list(hostnames),
            label=label or cn,
            provisioned_by=provisioned_by,
        )
    finally:
        db.close()

    click.echo(f"Provisioned:  {cn}")
    click.echo(f"Fingerprint:  {fingerprint}")
    click.echo(f"Hostnames:    {', '.join(hostnames)}")
    click.echo()
    click.echo(f"Bearer token: {token}")
    click.echo()
    click.secho("WARNING: Save this token — it will not be shown again.", fg="yellow", bold=True)
    click.echo("         Devices authenticate with:  Authorization: Bearer <token>")


# ── devices ───────────────────────────────────────────────────────────────────


@cli.command("devices")
@click.option("--all", "include_revoked", is_flag=True, default=False, help="Include revoked devices.")
@click.pass_context
def list_devices(ctx: click.Context, include_revoked: bool) -> None:
    """List provisioned devices."""
    db = _open_db(ctx)
    try:
        rows = DevicesDB(db).list_all(include_revoked=include_revoked)
    finally:
        db.close()

    if not rows:
        click.echo("No devices found.")
        return

    fmt = "{:<64}  {:<40}  {:<8}  {}"
    click.echo(fmt.format("FINGERPRINT", "CN", "STATUS", "LABEL"))
    click.echo("-" * 120)
    for d in rows:
        status = click.style("active", fg="green") if d.is_active else click.style("revoked", fg="red")
        click.echo(fmt.format(d.fingerprint, d.cn, status, d.label or ""))


# ── revoke ────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("fingerprint")
@click.option("--reason", default="unspecified", show_default=True, help="Revocation reason.")
@click.option("--by", "revoked_by", default="admin", show_default=True, help="Who is revoking this device.")
@click.pass_context
def revoke(ctx: click.Context, fingerprint: str, reason: str, revoked_by: str) -> None:
    """Revoke a device by fingerprint."""
    db = _open_db(ctx)
    try:
        result = DevicesDB(db).revoke(fingerprint, revoked_by, reason)
        AuditLog(db).record(AuditEntry(
            event=Event.DEVICE_REVOKED,
            actor=f"admin:{revoked_by}",
            outcome="success" if result else "noop",
            details={"fingerprint": fingerprint, "reason": reason},
        ))
    finally:
        db.close()

    if result:
        click.secho(f"Revoked: {fingerprint}", fg="red")
    else:
        click.echo(f"Device {fingerprint!r} was already revoked (no change).")


# ── unrevoke ──────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("fingerprint")
@click.option("--by", "unrevoked_by", default="admin", show_default=True)
@click.pass_context
def unrevoke(ctx: click.Context, fingerprint: str, unrevoked_by: str) -> None:
    """Re-activate a previously revoked device."""
    db = _open_db(ctx)
    try:
        result = DevicesDB(db).unrevoke(fingerprint)
        AuditLog(db).record(AuditEntry(
            event=Event.DEVICE_UNREVOKED,
            actor=f"admin:{unrevoked_by}",
            outcome="success" if result else "noop",
            details={"fingerprint": fingerprint},
        ))
    finally:
        db.close()

    if result:
        click.secho(f"Unrevoked: {fingerprint}", fg="green")
    else:
        click.echo(f"Device {fingerprint!r} was not revoked (no change).")


# ── certs ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("fingerprint")
@click.pass_context
def certs(ctx: click.Context, fingerprint: str) -> None:
    """List certificates issued to a device."""
    db = _open_db(ctx)
    try:
        rows = CertsDB(db).list_for_device(fingerprint)
    finally:
        db.close()

    if not rows:
        click.echo("No certificates found.")
        return

    now = datetime.now(timezone.utc)
    fmt = "{:<16}  {:<30}  {:<28}  {}"
    click.echo(fmt.format("SERIAL", "CN", "NOT AFTER", "STATUS"))
    click.echo("-" * 100)
    for c in rows:
        not_after = datetime.fromisoformat(c.not_after)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - now).days
        if days_left < 0:
            status = click.style("expired", fg="red")
        elif days_left <= 30:
            status = click.style(f"expiring ({days_left}d)", fg="yellow")
        else:
            status = click.style(f"valid ({days_left}d)", fg="green")
        click.echo(fmt.format(c.serial[:16], c.cn, c.not_after[:28], status))


# ── audit ─────────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--device", "device_fp", default=None, help="Filter by device fingerprint.")
@click.option("--event", "event_str", default=None, help="Filter by event type (e.g. sign.issued).")
@click.option("--outcome", default=None, help="Filter by outcome (success/failure).")
@click.option("--limit", default=50, show_default=True, help="Maximum number of rows to return.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output as JSON lines.")
@click.pass_context
def audit(
    ctx: click.Context,
    device_fp: str | None,
    event_str: str | None,
    outcome: str | None,
    limit: int,
    as_json: bool,
) -> None:
    """Query the audit log."""
    event = Event(event_str) if event_str else None

    db = _open_db(ctx)
    try:
        rows = AuditLog(db).query(
            device_fp=device_fp,
            event=event,
            outcome=outcome,
            limit=limit,
        )
    finally:
        db.close()

    if not rows:
        click.echo("No audit entries found.")
        return

    if as_json:
        for r in rows:
            click.echo(json.dumps({
                "ts": r.ts if isinstance(r.ts, str) else r.ts.isoformat(),
                "event": r.event.value,
                "actor": r.actor,
                "outcome": r.outcome,
                "device_fp": r.device_fp,
                "device_cn": r.device_cn,
                "source_ip": r.source_ip,
                "details": r.details,
            }))
        return

    fmt = "{:<26}  {:<28}  {:<9}  {:<20}  {}"
    click.echo(fmt.format("TIMESTAMP", "EVENT", "OUTCOME", "ACTOR", "SOURCE IP"))
    click.echo("-" * 100)
    for r in rows:
        ts_dt = datetime.fromisoformat(r.ts) if isinstance(r.ts, str) else r.ts
        ts = ts_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        outcome_styled = (
            click.style(r.outcome, fg="green") if r.outcome == "success"
            else click.style(r.outcome, fg="red")
        )
        click.echo(fmt.format(ts, r.event.value, outcome_styled, r.actor[:20], r.source_ip or ""))
