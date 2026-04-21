"""WSGI entry point — wires real dependencies from environment variables.

Environment variables
---------------------
CERTOVUS_ENV            dev | staging | production  (default: dev)
BROKER_DB_PATH          Path to SQLite DB           (default: /data/certovus.db)
ACME_ACCOUNT_KEY_PATH   Path to EC P-256 key PEM    (default: /data/acme_account.key)
PEBBLE_URL              ACME directory URL           (default: pebble URL)
CHALLTESTSRV_URL        challtestsrv base URL        (dev only)
CLOUDFLARE_API_TOKEN    Cloudflare API token         (staging/production)
CLOUDFLARE_ZONE_ID      Cloudflare zone ID           (staging/production)
RATE_PER_DEVICE         Per-device cert limit        (default: 1, 0 = disabled)
RATE_PER_DEVICE_HOURS   Per-device window hours      (default: 24)
RATE_GLOBAL             Global cert limit            (default: 50, 0 = disabled)
RATE_GLOBAL_DAYS        Global window days           (default: 7)
LOG_LEVEL               Python log level             (default: INFO)
"""

from __future__ import annotations

import logging
import os

from flask import Flask

from broker.acme_client import ACMEClient
from broker.app import create_app
from broker.audit import AuditLog
from broker.cache import CertCache
from broker.db import CertsDB, Database, DevicesDB
from broker.dns import DNSProvider
from broker.rate_limit import RateLimiter


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _int_env(key: str, default: int) -> int:
    return int(os.environ.get(key, default))


def _build_dns_provider() -> DNSProvider:
    env = _env("CERTOVUS_ENV", "dev")
    if env == "dev":
        challtestsrv_url = os.environ.get("CHALLTESTSRV_URL")
        if challtestsrv_url:
            from broker.dns.mock import MockDNS
            return MockDNS(challtestsrv_url=challtestsrv_url)
        from broker.dns.noop import NoopDNS
        return NoopDNS()
    from broker.dns.cloudflare import CloudflareDNS
    return CloudflareDNS(
        api_token=_env("CLOUDFLARE_API_TOKEN", ""),
        zone_id=_env("CLOUDFLARE_ZONE_ID", ""),
    )


def _build_app() -> Flask:
    logging.basicConfig(
        level=_env("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    env = _env("CERTOVUS_ENV", "dev")
    db_path = _env("BROKER_DB_PATH", "/data/certovus.db")
    acme_key_path = _env("ACME_ACCOUNT_KEY_PATH", "/data/acme_account.key")

    db = Database(db_path)
    db.connect()

    acme_directory = _env("PEBBLE_URL", "https://pebble:14000/dir")
    verify_ssl = env != "dev"

    acme_client = ACMEClient(
        directory_url=acme_directory,
        account_key_path=acme_key_path,
        verify_ssl=verify_ssl,
    )

    dns_provider = _build_dns_provider()

    devices_db = DevicesDB(db)
    certs_db = CertsDB(db)
    audit = AuditLog(db)
    cache = CertCache(certs_db)
    rate_limiter = RateLimiter(
        certs_db=certs_db,
        cache=cache,
        per_device_limit=_int_env("RATE_PER_DEVICE", 1),
        per_device_window_hours=_int_env("RATE_PER_DEVICE_HOURS", 24),
        global_limit=_int_env("RATE_GLOBAL", 50),
        global_window_days=_int_env("RATE_GLOBAL_DAYS", 7),
    )

    return create_app(
        acme_client=acme_client,
        dns_provider=dns_provider,
        rate_limiter=rate_limiter,
        cache=cache,
        audit=audit,
        devices_db=devices_db,
        certs_db=certs_db,
    )


app = _build_app()
