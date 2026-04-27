"""
60s sliding request counts: one deque of timestamps for all traffic, one deque per source_ip.

No rate-limiting libs — only collections.deque. Eviction: drop timestamps older than
now - window_seconds from the left (FIFO).

Memory: IPs we never see again still get swept on a timer so empty/stale deques
don't stick around forever.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any


class SlidingWindows:
    def __init__(
        self,
        window_seconds: float = 60.0,
        sweep_interval_seconds: float = 1.0,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._window = window_seconds
        self._sweep_interval = max(0.0, sweep_interval_seconds)
        self._global: deque[float] = deque()
        self._per_ip: dict[str, deque[float]] = {}
        self._last_sweep = 0.0

    @property
    def window_seconds(self) -> float:
        return self._window

    def _cutoff(self, now: float) -> float:
        return now - self._window

    def _prune(self, dq: deque[float], now: float) -> None:
        c = self._cutoff(now)
        while dq and dq[0] < c:
            dq.popleft()

    def _sweep_stale_ips(self, now: float) -> None:
        """drop timestamps older than the window; remove empty per-ip deques"""
        c = self._cutoff(now)
        for ip in list(self._per_ip.keys()):
            # get the deque for the ip
            dq = self._per_ip[ip]
            # prune the deque
            while dq and dq[0] < c:
                dq.popleft()
            if not dq:
                # if the deque is empty, delete it
                del self._per_ip[ip]

    def record(self, source_ip: str, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._prune(self._global, now)
        self._global.append(now)
        # get the deque for the ip
        if source_ip not in self._per_ip:
            self._per_ip[source_ip] = deque()
        ipq = self._per_ip[source_ip]
        # prune the deque
        self._prune(ipq, now)
        ipq.append(now)

        if self._sweep_interval > 0 and (now - self._last_sweep) >= self._sweep_interval:
            self._sweep_stale_ips(now)
            self._last_sweep = now

    def global_count(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        self._prune(self._global, now)
        return len(self._global)

    def ip_count(self, source_ip: str, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        if source_ip not in self._per_ip:
            return 0
        # get the deque for the ip
        dq = self._per_ip[source_ip]
        # prune the deque
        self._prune(dq, now)
        # return the length of the deque
        return len(dq)

    def global_rps(self, *, now: float | None = None) -> float:
        """rough req/s in the window = count / window length"""
        return self.global_count(now=now) / self._window

    def ip_rps(self, source_ip: str, *, now: float | None = None) -> float:
        return self.ip_count(source_ip, now=now) / self._window

    def snapshot(
        self,
        source_ip: str | None = None,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        """counts after pruning to 'now' (for logging / later dashboard)"""
        now = time.time() if now is None else now
        self._prune(self._global, now)
        # get the length of the global deque
        n_g = len(self._global)
        out: dict[str, Any] = {
            "window_seconds": self._window,
            "global_count": n_g,
            "global_rps": n_g / self._window,
        }
        if source_ip is not None:
            # get the deque for the ip
            c = 0
            if source_ip in self._per_ip:
                q = self._per_ip[source_ip]
                self._prune(q, now)
                c = len(q)
            out["ip"] = source_ip
            out["ip_count"] = c
            out["ip_rps"] = c / self._window
        return out
