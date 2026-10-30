"""In-process sliding-window rate limiting for the API.

A single shared token and a LAN bind mean an attacker who guesses the port can
hammer the API as fast as the network allows. This limiter keeps a small ring
of timestamps per client key and returns ``429`` with ``Retry-After`` once the
budget for the window is spent.

It is deliberately dependency-free and process-local: CloudSentinel serves one
uvicorn process on a laptop or a small server, so Redis or a shared store would
be complexity without a benefit. If the project ever runs multiple workers,
this class is the seam to replace.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque

# A laptop will never see thousands of distinct clients; the cap keeps memory
# bounded if something scans from many addresses.
MAX_CLIENTS = 4096


class SlidingWindowLimiter:
    """Allow ``limit`` requests per ``window_seconds`` for each key."""

    def __init__(
        self,
        limit: int,
        window_seconds: float = 60.0,
        *,
        clock=time.monotonic,
        max_clients: int = MAX_CLIENTS,
    ) -> None:
        self.limit = max(0, int(limit))
        self.window = float(window_seconds)
        self._clock = clock
        self._max_clients = max_clients
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.limit > 0

    def check(self, key: str) -> tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)`` for one request."""
        if not self.enabled:
            return True, 0

        now = self._clock()
        cutoff = now - self.window

        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                hits = self._hits[key] = deque()
            else:
                # Refresh LRU position for the eviction policy.
                self._hits.move_to_end(key)

            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self.limit:
                retry_after = self.window - (now - hits[0])
                return False, max(1, int(retry_after + 0.999))

            hits.append(now)

            while len(self._hits) > self._max_clients:
                self._hits.popitem(last=False)

            return True, 0

    def reset(self, key: str | None = None) -> None:
        """Forget the counters (used by tests and the ``/health`` probes)."""
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)
