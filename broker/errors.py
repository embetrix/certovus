"""Typed exceptions for Certovus.

Every external call (ACME, DNS, SQLite) raises one of these so callers can
handle failure modes precisely without catching broad Exception types.
"""


class CertovusError(Exception):
    """Base for all Certovus errors."""


class CSRError(CertovusError):
    """Invalid or structurally unacceptable CSR."""


class HostnameDeniedError(CertovusError):
    """CSR requests a hostname not in the device's allowlist."""


class RateLimitError(CertovusError):
    """Issuance refused — per-device or global rate limit reached."""


class ACMEError(CertovusError):
    """Error communicating with the ACME server or completing a challenge."""


class DNSError(CertovusError):
    """Error setting or deleting a DNS challenge TXT record."""


class DeviceNotFoundError(CertovusError):
    """No device with the given fingerprint or CN exists in the DB."""


class DeviceRevokedError(CertovusError):
    """Device exists but has been administratively revoked."""


class NoClientCertError(CertovusError):
    """Request arrived without a client certificate — nginx misconfiguration."""
