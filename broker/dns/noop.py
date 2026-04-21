"""No-op DNS provider for testing with PEBBLE_VA_ALWAYS_VALID=1.

Pebble skips DNS validation entirely when that flag is set, so TXT records
don't need to exist.  This provider satisfies the DNSProvider interface
without touching any external service.
"""

from __future__ import annotations

import logging

from broker.dns import DNSProvider

logger = logging.getLogger(__name__)


class NoopDNS(DNSProvider):
    """DNS provider that accepts all calls without doing anything."""

    def set_txt(self, domain: str, value: str) -> None:
        logger.debug("noop dns: set_txt %s = %s", domain, value)

    def delete_txt(self, domain: str) -> None:
        logger.debug("noop dns: delete_txt %s", domain)

    def wait_for_propagation(self, domain: str, value: str) -> None:
        logger.debug("noop dns: wait_for_propagation %s", domain)
