"""
Sliding 60s windows: all-request timestamps in deques, plus 4xx/5xx in parallel deques.

Eviction: pop left while timestamp < now - window_seconds. No rate-limiting libs.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any


def _is_client_or_server_error(status: int) -> bool:
    return 400 <= status < 600


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
        self._global_err: deque[float] = deque()
        self._per_ip_err: dict[str, deque[float]] = {}
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
        c = self._cutoff(now)
        for ip in list(self._per_ip.keys()):
            dq = self._per_ip[ip]
            while dq and dq[0] < c:
                dq.popleft()
            if not dq:
                del self._per_ip[ip]
        for ip in list(self._per_ip_err.keys()):
            dq = self._per_ip_err[ip]
            while dq and dq[0] < c:
                dq.popleft()
            if not dq:
                del self._per_ip_err[ip]

    def record(self, source_ip: str, *, status: int | None = None, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._prune(self._global, now)
        self._global.append(now)
        if source_ip not in self._per_ip:
            self._per_ip[source_ip] = deque()
        ipq = self._per_ip[source_ip]
        self._prune(ipq, now)
        ipq.append(now)
        if status is not None and _is_client_or_server_error(int(status)):
            self._prune(self._global_err, now)
            self._global_err.append(now)
            if source_ip not in self._per_ip_err:
                self._per_ip_err[source_ip] = deque()
            eq = self._per_ip_err[source_ip]
            self._prune(eq, now)
            eq.append(now)
        if self._sweep_interval > 0 and (now - self._last_sweep) >= self._sweep_interval:
            self._prune(self._global_err, now)
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
        dq = self._per_ip[source_ip]
        self._prune(dq, now)
        return len(dq)

    def global_error_count(self, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        self._prune(self._global_err, now)
        return len(self._global_err)

    def ip_error_count(self, source_ip: str, *, now: float | None = None) -> int:
        now = time.time() if now is None else now
        if source_ip not in self._per_ip_err:
            return 0
        dq = self._per_ip_err[source_ip]
        self._prune(dq, now)
        return len(dq)

    def global_rps(self, *, now: float | None = None) -> float:
        return self.global_count(now=now) / self._window

    def ip_rps(self, source_ip: str, *, now: float | None = None) -> float:
        return self.ip_count(source_ip, now=now) / self._window

    def global_error_rps(self, *, now: float | None = None) -> float:
        return self.global_error_count(now=now) / self._window

    def ip_error_rps(self, source_ip: str, *, now: float | None = None) -> float:
        return self.ip_error_count(source_ip, now=now) / self._window

    def top_source_ips(self, n: int, *, now: float | None = None) -> list[tuple[str, int]]:
        now = time.time() if now is None else now
        scored: list[tuple[str, int]] = []
        for ip, dq in list(self._per_ip.items()):
            self._prune(dq, now)
            c = len(dq)
            if c > 0:
                scored.append((ip, c))
        scored.sort(key=lambda t: -t[1])
        return scored[:n]

    def snapshot(
        self,
        source_ip: str | None = None,
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        now = time.time() if now is None else now
        self._prune(self._global, now)
        n_g = len(self._global)
        out: dict[str, Any] = {
            "window_seconds": self._window,
            "global_count": n_g,
            "global_rps": n_g / self._window,
        }
        if source_ip is not None:
            c = 0
            if source_ip in self._per_ip:
                q = self._per_ip[source_ip]
                self._prune(q, now)
                c = len(q)
            out["ip"] = source_ip
            out["ip_count"] = c
            out["ip_rps"] = c / self._window
        return out
