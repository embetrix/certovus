"""DB-backed certificate cache.

Cache hit (get): same device + same CSR hash → return existing cert if >30 days remain.
Expiry check (is_expiring): True when the device's best cert has ≤30 days left (or none).
The rate limiter uses is_expiring() to waive the per-device 24 h limit.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from broker.db import CertsDB, IssuedCert

EXPIRY_THRESHOLD = timedelta(days=30)


def _days_remaining(cert: IssuedCert) -> float:
    not_after = datetime.fromisoformat(cert.not_after)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return (not_after - datetime.now(timezone.utc)).total_seconds() / 86400


def _is_fresh(cert: IssuedCert) -> bool:
    """Return True if cert has strictly more than 30 days remaining."""
    not_after = datetime.fromisoformat(cert.not_after)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return not_after - datetime.now(timezone.utc) > EXPIRY_THRESHOLD


class CertCache:
    """Certificate cache backed by the issued_certs DB table."""

    def __init__(self, certs_db: CertsDB) -> None:
        self._db = certs_db

    def get(self, device_fp: str, csr_hash: str) -> Optional[IssuedCert]:
        """Return the cached cert for this device+CSR if it has >30 days remaining.

        Returns None on cache miss or if the cached cert is expiring soon.
        """
        cert = self._db.get_by_csr_hash(device_fp, csr_hash)
        if cert is None:
            return None
        return cert if _is_fresh(cert) else None

    def get_best(self, device_fp: str) -> Optional[IssuedCert]:
        """Return the cert with the longest remaining validity, or None if none exists."""
        return self._db.get_best_cert(device_fp)

    def is_expiring(self, device_fp: str) -> bool:
        """Return True if the best live cert has ≤30 days remaining, or no cert exists.

        Used by the rate limiter to bypass the per-device 24 h issuance limit.
        """
        best = self.get_best(device_fp)
        return best is None or not _is_fresh(best)
