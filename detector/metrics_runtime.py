"""Process-wide counters for the dashboard (thread-safe)."""

from __future__ import annotations

import threading
import time


class RuntimeMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.t0 = time.time()
        self.events = 0

    def bump(self) -> None:
        with self._lock:
            self.events += 1

    def uptime_s(self) -> float:
        return time.time() - self.t0

    @property
    def event_count(self) -> int:
        with self._lock:
            return self.events
