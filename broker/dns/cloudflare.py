"""Cloudflare DNS adapter for ACME DNS-01 challenges.

Scoped to TXT record operations on a single zone.  The API token must have
``Zone:DNS:Edit`` permission for the ``embetrix.works`` zone only — it must
never have write access to other zones or to zone settings.

Propagation is confirmed by polling Cloudflare's own public resolver (1.1.1.1)
so the check reflects what Let's Encrypt's verifier is likely to see.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import cloudflare as cf_sdk
import dns.exception
import dns.resolver

from broker.dns import DNSProvider, challenge_record_name
from broker.errors import DNSError

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_CF_RESOLVER = "1.1.1.1"   # Cloudflare's public resolver — authoritative fastest
_TXT_TTL     = 60           # seconds; minimum allowed by Cloudflare


class CloudflareDNS(DNSProvider):
    """Production DNS provider backed by the Cloudflare API.

    Args:
        api_token:            Cloudflare API token (Zone:DNS:Edit on target zone).
        zone_id:              Cloudflare zone ID for ``embetrix.works``.
        propagation_timeout:  Seconds to wait for the record to appear in DNS.
        poll_interval:        Seconds between DNS resolution polls.
    """

    def __init__(
        self,
        api_token: str,
        zone_id: str,
        propagation_timeout: int = 120,
        poll_interval: int = 5,
    ) -> None:
        self._client = cf_sdk.Cloudflare(api_token=api_token)
        self._zone_id = zone_id
        self._propagation_timeout = propagation_timeout
        self._poll_interval = poll_interval

    # ── DNSProvider interface ─────────────────────────────────────────────────

    def set_txt(self, domain: str, value: str) -> None:
        """Create the challenge TXT record, replacing any pre-existing one."""
        name = challenge_record_name(domain)
        self._delete_existing(name)
        try:
            self._client.dns.records.create(
                zone_id=self._zone_id,
                type="TXT",
                name=name,
                content=value,
                ttl=_TXT_TTL,
            )
            logger.debug("cloudflare: set TXT %s", name)
        except cf_sdk.APIError as exc:
            raise DNSError(f"Cloudflare set_txt failed for {name}: {exc}") from exc

    def delete_txt(self, domain: str) -> None:
        """Remove all challenge TXT records for *domain*.  Idempotent."""
        name = challenge_record_name(domain)
        try:
            self._delete_existing(name)
        except DNSError:
            raise
        except Exception as exc:
            raise DNSError(f"Cloudflare delete_txt failed for {name}: {exc}") from exc

    def wait_for_propagation(self, domain: str, value: str) -> None:
        """Poll 1.1.1.1 until the TXT value appears or the timeout expires."""
        name = challenge_record_name(domain)
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [_CF_RESOLVER]

        deadline = time.monotonic() + self._propagation_timeout
        while time.monotonic() < deadline:
            if _txt_value_visible(resolver, name, value):
                logger.debug("cloudflare: TXT %s propagated", name)
                return
            time.sleep(self._poll_interval)

        raise DNSError(
            f"TXT record {name!r} did not propagate within {self._propagation_timeout}s"
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _delete_existing(self, name: str) -> None:
        """Delete all TXT records with the given name in this zone."""
        try:
            existing = list(
                self._client.dns.records.list(
                    zone_id=self._zone_id,
                    type="TXT",
                    name=name,  # type: ignore[arg-type]
                )
            )
            for record in existing:
                self._client.dns.records.delete(record.id, zone_id=self._zone_id)
                logger.debug("cloudflare: deleted existing TXT %s id=%s", name, record.id)
        except cf_sdk.APIError as exc:
            raise DNSError(f"Cloudflare delete_existing failed for {name}: {exc}") from exc


def _txt_value_visible(resolver: dns.resolver.Resolver, name: str, value: str) -> bool:
    """Return True if *value* appears in any TXT RDATA for *name*."""
    try:
        answers = resolver.resolve(name, "TXT", lifetime=10.0)
        for rdata in answers:
            for string in rdata.strings:
                if string.decode() == value:
                    return True
    except (dns.exception.DNSException, Exception):
        pass
    return False
