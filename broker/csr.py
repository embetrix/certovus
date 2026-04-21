"""CSR parsing, validation, and hostname enforcement.

The broker receives raw PEM CSRs from devices and must verify them before
handing them to the ACME client.  Three things are checked:

1. The CSR is structurally valid and the signature is self-consistent.
2. Every requested name (CN + DNS SANs) is in the device's hostname allowlist.
3. No non-DNS SANs are present (LE DNS-01 only covers DNS names; IP/email SANs
   would either be rejected by LE or silently dropped, so we fail early).

The stable CSR hash (SHA-256 of DER) is the cache key used by broker/cache.py
to return a previously-issued certificate for the same request.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from broker.errors import CSRError, HostnameDeniedError


@dataclass
class ParsedCSR:
    """Validated, parsed representation of a PEM CSR."""

    cn: str                     # CommonName from the subject
    sans: list[str]             # DNS SANs only (empty if extension absent)
    requested_names: list[str]  # deduplicated [cn] + sans — what LE will certify
    csr_hash: str               # SHA-256 hex of DER — stable cache / rate-limit key
    pem: str                    # original PEM (whitespace-stripped)


def parse_csr(pem: str) -> ParsedCSR:
    """Parse and validate a PEM-encoded CSR.

    Raises:
        CSRError: PEM is malformed, signature is invalid, CN is missing,
                  or non-DNS SANs are present.
    """
    pem = pem.strip()
    if not pem:
        raise CSRError("empty CSR")

    try:
        csr = x509.load_pem_x509_csr(pem.encode())
    except (ValueError, TypeError) as exc:
        raise CSRError(f"failed to parse CSR: {exc}") from exc

    try:
        sig_valid = csr.is_signature_valid
    except ValueError as exc:
        # Raised when the embedded public key is itself malformed/tampered.
        raise CSRError(f"CSR signature check failed: {exc}") from exc
    if not sig_valid:
        raise CSRError("CSR signature is invalid")

    # CN is required — LE uses it as the primary identifier.
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise CSRError("CSR subject has no Common Name")
    cn = str(cn_attrs[0].value)

    # Extract DNS SANs; reject any non-DNS SAN (IP, email, URI, …).
    sans: list[str] = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            else:
                raise CSRError(
                    f"CSR contains non-DNS SAN ({type(name).__name__}); "
                    "only DNS names are supported"
                )
    except x509.ExtensionNotFound:
        pass  # SANs extension is optional; CN alone is fine

    # requested_names: CN first, then any additional SANs, deduplicated.
    seen: set[str] = set()
    requested_names: list[str] = []
    for name in [cn, *sans]:
        if name not in seen:
            seen.add(name)
            requested_names.append(name)

    csr_hash = hashlib.sha256(csr.public_bytes(Encoding.DER)).hexdigest()

    return ParsedCSR(
        cn=cn,
        sans=sans,
        requested_names=requested_names,
        csr_hash=csr_hash,
        pem=pem,
    )


def validate_hostnames(parsed: ParsedCSR, allowed: list[str]) -> None:
    """Assert every requested name is in the device's hostname allowlist.

    Raises:
        HostnameDeniedError: one or more names are not in the allowlist.
    """
    allowed_set = set(allowed)
    denied = [n for n in parsed.requested_names if n not in allowed_set]
    if denied:
        raise HostnameDeniedError(
            f"hostname(s) not in device allowlist: {', '.join(denied)}"
        )
