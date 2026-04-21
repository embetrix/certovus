"""In-process ACME v2 client for DNS-01 certificate issuance.

Never shells out to certbot or acme.sh — the full RFC 8555 protocol runs
here using the ``acme`` library from the certbot project.

Issuance lifecycle per call to issue():
  1. Create ACME order (domains extracted from CSR by the library)
  2. For each authorization, find the DNS-01 challenge
  3. Set TXT records for all domains via the DNS provider
  4. Wait for propagation of all records
  5. Notify ACME server (answer challenges)
  6. poll_and_finalize: poll authorizations → finalize order → poll cert → download
  7. Always delete TXT records in a finally block, even on failure

Account key lifecycle:
  - EC P-256, stored as PKCS8 PEM at the configured path
  - Created on first use with chmod 0600; never regenerated if file exists
  - Never logged
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import josepy
from acme import challenges
from acme import client as acme_lib
from acme import errors as acme_errors
from acme import messages
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from broker.dns import DNSProvider
from broker.errors import ACMEError

logger = logging.getLogger(__name__)


class ACMEClient:
    """Wraps ``acme.client.ClientV2`` with account-key management and DNS-01 flow.

    Args:
        directory_url:     ACME directory URL.  Use pebble's URL in dev,
                           LE staging/prod in other envs.
        account_key_path:  Path to the EC P-256 account key PEM (created if absent).
        verify_ssl:        Set False for pebble (self-signed TLS).
        order_timeout:     Seconds to wait for each order to complete.
    """

    def __init__(
        self,
        directory_url: str,
        account_key_path: str,
        verify_ssl: bool = True,
        order_timeout: int = 90,
    ) -> None:
        self._directory_url = directory_url
        self._account_key_path = Path(account_key_path)
        self._verify_ssl = verify_ssl
        self._order_timeout = order_timeout
        self._acme: Optional[acme_lib.ClientV2] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def issue(self, csr_pem: str, dns_provider: DNSProvider) -> str:
        """Run the full DNS-01 flow and return the issued PEM certificate chain.

        TXT records are always cleaned up, even if the order fails.

        Raises:
            ACMEError: on any ACME or DNS failure.
        """
        acme = self._get_client()

        try:
            order = acme.new_order(csr_pem.encode())
        except acme_errors.Error as exc:
            raise ACMEError(f"failed to create ACME order: {exc}") from exc

        # Collect challenges before touching DNS — fail fast if any domain is missing one.
        challbs = _collect_dns01_challenges(order, acme.net.key)

        # Set all TXT records first so we can wait for all of them in parallel.
        _set_all_txt(challbs, dns_provider)
        try:
            _wait_all_propagation(challbs, dns_provider)
            _answer_all(challbs, acme)
            deadline = datetime.now() + timedelta(seconds=self._order_timeout)
            try:
                order = acme.poll_and_finalize(order, deadline=deadline)
            except acme_errors.Error as exc:
                raise ACMEError(f"ACME order failed: {exc}") from exc
        finally:
            _delete_all_txt(challbs, dns_provider)

        if not order.fullchain_pem:
            raise ACMEError("ACME order completed but no certificate was returned")

        logger.info("acme: issued cert for order %s", order.uri)
        return order.fullchain_pem

    def revoke(self, cert_pem: str, reason: int = 0) -> None:
        """Revoke a certificate via ACME.

        Args:
            cert_pem: PEM-encoded certificate to revoke.
            reason:   RFC 5280 CRLReason code (0 = unspecified, 1 = keyCompromise, …).

        Raises:
            ACMEError: if the ACME server rejects the revocation.
        """
        acme = self._get_client()
        try:
            from cryptography.x509 import load_pem_x509_certificate
            cert = load_pem_x509_certificate(cert_pem.encode())
            acme.revoke(cert, reason)
            logger.info("acme: revoked certificate (reason=%d)", reason)
        except acme_errors.Error as exc:
            raise ACMEError(f"ACME revocation failed: {exc}") from exc
        except Exception as exc:
            raise ACMEError(f"revocation error: {exc}") from exc

    # ── Client initialisation ─────────────────────────────────────────────────

    def _get_client(self) -> acme_lib.ClientV2:
        if self._acme is None:
            self._acme = self._build_client()
        return self._acme

    def _build_client(self) -> acme_lib.ClientV2:
        jwk = self._load_or_create_account_key()
        net = acme_lib.ClientNetwork(
            jwk,
            alg=josepy.ES256,
            verify_ssl=self._verify_ssl,
            user_agent="certovus/0.1.0",
        )
        try:
            directory = messages.Directory.from_json(net.get(self._directory_url).json())
        except Exception as exc:
            raise ACMEError(f"failed to fetch ACME directory {self._directory_url!r}: {exc}") from exc

        client = acme_lib.ClientV2(directory, net)

        try:
            reg = messages.NewRegistration.from_data(terms_of_service_agreed=True)
            regr = client.new_account(reg)
            net.account = regr
            logger.info("acme: account ready (uri=%s)", regr.uri)
        except acme_errors.Error as exc:
            raise ACMEError(f"ACME account registration failed: {exc}") from exc

        return client

    def _load_or_create_account_key(self) -> josepy.JWKEC:
        """Return the account JWK, creating the key file (0600) if it does not exist."""
        if self._account_key_path.exists():
            try:
                raw = self._account_key_path.read_bytes()
                private_key = load_pem_private_key(raw, password=None)
                if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                    raise ACMEError(
                        f"account key {self._account_key_path} is not an EC key; "
                        "delete it to generate a fresh P-256 key"
                    )
                logger.debug("acme: loaded account key from %s", self._account_key_path)
                return josepy.JWKEC(key=private_key)
            except (ValueError, TypeError) as exc:
                raise ACMEError(
                    f"failed to load account key from {self._account_key_path}: {exc}"
                ) from exc

        # Generate fresh P-256 key.
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        self._account_key_path.parent.mkdir(parents=True, exist_ok=True)
        self._account_key_path.write_bytes(pem)
        os.chmod(self._account_key_path, 0o600)
        logger.info("acme: generated new account key at %s", self._account_key_path)
        return josepy.JWKEC(key=private_key)


# ── Challenge helpers (module-level so they're independently testable) ────────


def _collect_dns01_challenges(
    order: messages.OrderResource,
    account_key: josepy.JWK,
) -> list[tuple[str, object, object, str]]:
    """Return list of (domain, challenge_body, response, txt_value) for all authzrs.

    Skips authorizations that are already valid (ACME server may reuse them).
    Raises ACMEError if any pending authorization has no DNS-01 challenge.
    """
    result = []
    for authzr in order.authorizations:
        if authzr.body.status == messages.STATUS_VALID:
            continue
        domain = authzr.body.identifier.value
        dns01 = next(
            (c for c in authzr.body.challenges if isinstance(c.chall, challenges.DNS01)),
            None,
        )
        if dns01 is None:
            raise ACMEError(
                f"ACME server offered no DNS-01 challenge for {domain!r}; "
                "check that the domain is in the zone controlled by your DNS provider"
            )
        response, validation = dns01.chall.response_and_validation(account_key)
        result.append((domain, dns01, response, validation))
    return result


def _set_all_txt(
    challbs: list[tuple[str, object, object, str]],
    provider: DNSProvider,
) -> None:
    """Set TXT records for all challenges.  Cleans up on partial failure."""
    set_so_far: list[str] = []
    for domain, _, _, validation in challbs:
        try:
            provider.set_txt(domain, validation)
            set_so_far.append(domain)
        except Exception as exc:
            for d in set_so_far:
                try:
                    provider.delete_txt(d)
                except Exception:
                    pass
            raise ACMEError(f"failed to set DNS TXT for {domain!r}: {exc}") from exc


def _wait_all_propagation(
    challbs: list[tuple[str, object, object, str]],
    provider: DNSProvider,
) -> None:
    for domain, _, _, validation in challbs:
        try:
            provider.wait_for_propagation(domain, validation)
        except Exception as exc:
            raise ACMEError(f"DNS propagation timed out for {domain!r}: {exc}") from exc


def _answer_all(
    challbs: list[tuple[str, object, object, str]],
    acme: acme_lib.ClientV2,
) -> None:
    for _, challenge, response, _ in challbs:
        try:
            acme.answer_challenge(challenge, response)
        except acme_errors.Error as exc:
            raise ACMEError(f"failed to answer ACME challenge: {exc}") from exc


def _delete_all_txt(
    challbs: list[tuple[str, object, object, str]],
    provider: DNSProvider,
) -> None:
    """Best-effort TXT record cleanup.  Logs failures, never raises."""
    for domain, _, _, _ in challbs:
        try:
            provider.delete_txt(domain)
        except Exception as exc:
            logger.warning("acme: failed to clean up TXT for %s: %s", domain, exc)
