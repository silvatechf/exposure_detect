"""Tiny in-memory sliding-window limiter (per process; use a gateway for multi-instance setups)."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, max_calls: int, window: float = 60.0) -> None:
        self.max_calls, self.window = max_calls, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_calls:
            return False
        q.append(now)
        return True
