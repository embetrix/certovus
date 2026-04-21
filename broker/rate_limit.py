"""Per-device and global certificate issuance rate limits.

Both limits are configurable; set either to 0 to disable it entirely
(useful in dev/test environments).

Guards:
  - Per-device: at most ``per_device_limit`` certs in the last
    ``per_device_window_hours`` hours.  Bypassed when the device's best
    live cert has ≤30 days remaining (CertCache.is_expiring).
  - Global: at most ``global_limit`` certs issued across all devices in
    the last ``global_window_days`` days.  Never bypassed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from broker.cache import CertCache
from broker.db import CertsDB
from broker.errors import RateLimitError


class RateLimiter:
    """Raises RateLimitError if either rate limit is exceeded.

    Args:
        certs_db:               CertsDB instance for counting issued certs.
        cache:                  CertCache instance for expiry bypass check.
        per_device_limit:       Max certs per device per window. 0 = disabled.
        per_device_window_hours: Rolling window size for per-device limit.
        global_limit:           Max certs across all devices per window. 0 = disabled.
        global_window_days:     Rolling window size for global limit.
    """

    def __init__(
        self,
        certs_db: CertsDB,
        cache: CertCache,
        per_device_limit: int = 1,
        per_device_window_hours: int = 24,
        global_limit: int = 50,
        global_window_days: int = 7,
    ) -> None:
        self._db = certs_db
        self._cache = cache
        self._per_device_limit = per_device_limit
        self._per_device_window = timedelta(hours=per_device_window_hours)
        self._global_limit = global_limit
        self._global_window = timedelta(days=global_window_days)

    def check(self, device_fp: str) -> None:
        """Raise RateLimitError if the device should not receive a new cert.

        Always checks the global limit first, then the per-device limit.
        The per-device limit is skipped when the device's best cert is expiring.
        """
        self._check_global()
        self._check_per_device(device_fp)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _check_global(self) -> None:
        if self._global_limit == 0:
            return
        since = datetime.now(UTC) - self._global_window
        count = self._db.count_issued_since(since)
        if count >= self._global_limit:
            raise RateLimitError(
                f"global issuance limit reached: {count} certs issued in the last "
                f"{self._global_window.days} days (limit {self._global_limit})"
            )

    def _check_per_device(self, device_fp: str) -> None:
        if self._per_device_limit == 0:
            return
        if self._cache.is_expiring(device_fp):
            return
        since = datetime.now(UTC) - self._per_device_window
        count = self._db.count_issued_since_for_device(device_fp, since)
        if count >= self._per_device_limit:
            raise RateLimitError(
                f"per-device issuance limit reached: {count} certs issued in the last "
                f"{int(self._per_device_window.total_seconds() // 3600)} hours "
                f"(limit {self._per_device_limit})"
            )
