"""Mock DNS provider for local development against pebble-challtestsrv.

challtestsrv exposes an HTTP management API that pebble queries directly for
DNS-01 validation.  This provider POSTs to that API instead of touching
real DNS infrastructure.

challtestsrv management API (default port 8055):
    POST /set-txt   {"host": "<fqdn>.", "value": "<txt-value>"}
    POST /clear-txt {"host": "<fqdn>."}

The trailing dot is required by challtestsrv's DNS implementation.
"""

from __future__ import annotations

import logging
import time

import requests

from broker.dns import DNSProvider, challenge_record_name
from broker.errors import DNSError

logger = logging.getLogger(__name__)


class MockDNS(DNSProvider):
    """DNS provider that writes TXT records to a running pebble-challtestsrv.

    Args:
        challtestsrv_url:  Base URL of challtestsrv, e.g. ``http://challtestsrv:8055``.
        propagation_wait:  Seconds to sleep in wait_for_propagation.  challtestsrv
                           answers immediately so a small sleep (default 1 s) is
                           enough for pebble to pick up the record before challenge
                           validation begins.
    """

    def __init__(
        self,
        challtestsrv_url: str,
        propagation_wait: float = 1.0,
    ) -> None:
        self._url = challtestsrv_url.rstrip("/")
        self._propagation_wait = propagation_wait

    # ── DNSProvider interface ─────────────────────────────────────────────────

    def set_txt(self, domain: str, value: str) -> None:
        host = _fqdn(challenge_record_name(domain))
        self._post("/set-txt", {"host": host, "value": value})
        logger.debug("mock-dns: set TXT %s", host)

    def delete_txt(self, domain: str) -> None:
        host = _fqdn(challenge_record_name(domain))
        self._post("/clear-txt", {"host": host})
        logger.debug("mock-dns: cleared TXT %s", host)

    def wait_for_propagation(self, domain: str, value: str) -> None:
        # challtestsrv is in-process with pebble; no real propagation delay.
        if self._propagation_wait > 0:
            time.sleep(self._propagation_wait)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> None:
        url = f"{self._url}{path}"
        try:
            resp = requests.post(url, json=payload, timeout=10)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise DNSError(f"challtestsrv {path} failed ({url}): {exc}") from exc


def _fqdn(name: str) -> str:
    """Ensure *name* ends with a trailing dot as required by challtestsrv."""
    return name if name.endswith(".") else f"{name}."
