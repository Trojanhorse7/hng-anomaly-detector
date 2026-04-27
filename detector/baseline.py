"""
Rolling baseline: per-second global counts (all requests + 4xx/5xx errors), 30m window,
recompute on a timer. Hourly slice when enough samples. Floors + audit.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def _mean_std_sample(vals: list[int]) -> tuple[float, float]:
    n = len(vals)
    if n == 0:
        return 0.0, 0.0
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    return mean, math.sqrt(var)


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """snapshot after recompute — used by detection for z-score vs mean/std"""
    effective_mean: float
    effective_std: float
    error_effective_mean: float
    error_effective_std: float
    source: str  # "current_hour" or "full_window"
    n_samples: int
    total_requests_in_window: int
    total_errors_in_window: int


class RollingBaseline:
    """Global per-second total + error counts; ``record(is_error=...)`` each line."""

    def __init__(self, config: dict) -> None:
        self._lock = threading.Lock()
        self._window = int(config.get("baseline_window_seconds", 1800))
        self._recompute_s = int(config.get("baseline_recompute_interval_seconds", 60))
        self._floor = float(config.get("baseline_floor_rps", 0.0))
        self._min_std = float(config.get("baseline_min_std", 1e-6))
        self._min_samples_ch = int(config.get("baseline_min_samples_current_hour", 60))
        self._audit_path: str | None = config.get("audit_log_path") or None
        self._per_sec: dict[int, int] = defaultdict(int)
        self._per_sec_err: dict[int, int] = defaultdict(int)
        self._last: BaselineResult | None = None

    def record(self, *, is_error: bool = False, now: float | None = None) -> None:
        s = int(time.time() if now is None else now)
        c = s - self._window - 120
        with self._lock:
            self._per_sec[s] += 1
            if is_error:
                self._per_sec_err[s] += 1
            for d in (self._per_sec, self._per_sec_err):
                for k in list(d.keys()):
                    if k < c:
                        del d[k]

    def _vector_last(self, end_sec: int) -> list[int]:
        start = end_sec - self._window
        with self._lock:
            return [int(self._per_sec.get(s, 0)) for s in range(start, end_sec)]

    def _vector_last_err(self, end_sec: int) -> list[int]:
        start = end_sec - self._window
        with self._lock:
            return [int(self._per_sec_err.get(s, 0)) for s in range(start, end_sec)]

    def recompute(self, now: float | None = None) -> BaselineResult:
        now = time.time() if now is None else now
        end = int(now)
        vals_full = self._vector_last(end)
        vals_err = self._vector_last_err(end)
        h_now = datetime.fromtimestamp(end, tz=timezone.utc).hour
        idx_ch: list[int] = []
        for i, se in enumerate(range(end - self._window, end)):
            if datetime.fromtimestamp(se, tz=timezone.utc).hour == h_now:
                idx_ch.append(i)
        use_ch = len(idx_ch) >= self._min_samples_ch
        if use_ch:
            vals = [vals_full[i] for i in idx_ch]
            vals_e = [vals_err[i] for i in idx_ch]
            src = "current_hour"
        else:
            vals = vals_full
            vals_e = vals_err
            src = "full_window"
        m, s = _mean_std_sample(vals)
        me, se_ = _mean_std_sample(vals_e)
        m = max(m, self._floor)
        s = max(s, self._min_std)
        me = max(me, 0.0)
        se_ = max(se_, self._min_std)
        tot = sum(vals_full)
        tote = sum(vals_err)
        res = BaselineResult(
            effective_mean=m,
            effective_std=s,
            error_effective_mean=me,
            error_effective_std=se_,
            source=src,
            n_samples=len(vals),
            total_requests_in_window=tot,
            total_errors_in_window=tote,
        )
        self._last = res
        return res

    @property
    def last(self) -> BaselineResult | None:
        return self._last

    def append_audit_recalc(
        self,
        result: BaselineResult,
        now: float | None = None,
    ) -> None:
        if not self._audit_path:
            return
        now = time.time() if now is None else now
        ts = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rate_full = result.total_requests_in_window / self._window if self._window else 0.0
        line = (
            f"[{ts}] BASELINE_RECALC GLOBAL | {result.source} | {rate_full:.6f} | "
            f"{result.effective_mean:.6f}|{result.effective_std:.6f} | {self._window}s"
        )
        p = Path(self._audit_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        log.debug("audit: %s", line.rstrip())

    @property
    def recompute_interval(self) -> int:
        return self._recompute_s


def start_baseline_recompute_thread(
    baseline: RollingBaseline,
    should_stop: threading.Event,
) -> None:
    def _run() -> None:
        t = 2.0
        while not should_stop.is_set():
            if should_stop.wait(timeout=t):
                break
            t = float(baseline.recompute_interval)
            try:
                r = baseline.recompute()
                baseline.append_audit_recalc(r)
                log.info(
                    "baseline: mean=%.4f std=%.4f err_m=%.4f n=%d total30m=%d",
                    r.effective_mean,
                    r.effective_std,
                    r.error_effective_mean,
                    r.n_samples,
                    r.total_requests_in_window,
                )
            except Exception:  # noqa: BLE001
                log.exception("baseline recompute failed")

    th = threading.Thread(target=_run, name="baseline-recompute", daemon=True)
    th.start()
