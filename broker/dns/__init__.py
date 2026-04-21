"""DNS provider interface for ACME DNS-01 challenge management.

Concrete implementations:
  CloudflareDNS — production, uses the Cloudflare API
  MockDNS       — local dev, writes to pebble-challtestsrv

The ACME client calls providers in this sequence for each challenge domain:

    provider.set_txt(domain, value)
    provider.wait_for_propagation(domain, value)
    # ... notify ACME server, wait for validation ...
    provider.delete_txt(domain)          # always, even on failure
"""

from __future__ import annotations

from abc import ABC, abstractmethod


def challenge_record_name(domain: str) -> str:
    """Return the ACME DNS-01 challenge TXT record name for *domain*.

    Example: ``dev-01.embetrix.works`` → ``_acme-challenge.dev-01.embetrix.works``
    """
    return f"_acme-challenge.{domain}"


class DNSProvider(ABC):
    """Abstract base for DNS providers.  All methods operate on the
    ``_acme-challenge.<domain>`` TXT record; callers pass the bare domain.
    """

    @abstractmethod
    def set_txt(self, domain: str, value: str) -> None:
        """Create (or replace) the ``_acme-challenge.<domain>`` TXT record.

        Raises DNSError on any API or network failure.
        """

    @abstractmethod
    def delete_txt(self, domain: str) -> None:
        """Remove the ``_acme-challenge.<domain>`` TXT record.

        Must be idempotent — if no record exists the call should succeed silently.
        Raises DNSError only on genuine API failures.
        """

    @abstractmethod
    def wait_for_propagation(self, domain: str, value: str) -> None:
        """Block until the TXT record is visible to the ACME server's resolver.

        Raises DNSError if the record does not appear within the provider's
        configured timeout.
        """
