"""
Rolling baseline: mean + population std of per-second global request counts over a
configurable window (default 30 minutes); recomputed on a timer. Prefer stats from the
current UTC hour in that window when there are enough samples. Floors in config. Audit line on each recompute.
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
    """last effective values after recompute (for dashboard / detection later)"""
    effective_mean: float
    effective_std: float
    source: str  # "current_hour" or "full_window"
    n_samples: int
    total_requests_in_window: int


class RollingBaseline:
    """
    Global per-second request counts. ``record()`` on each request; a timer thread
    in main calls ``recompute()`` every N seconds and writes the audit line.
    """

    def __init__(self, config: dict) -> None:
        self._lock = threading.Lock()
        self._window = int(config.get("baseline_window_seconds", 1800))
        self._recompute_s = int(config.get("baseline_recompute_interval_seconds", 60))
        self._floor = float(config.get("baseline_floor_rps", 0.0))
        self._min_std = float(config.get("baseline_min_std", 1e-6))
        self._min_samples_ch = int(config.get("baseline_min_samples_current_hour", 60))
        self._audit_path: str | None = config.get("audit_log_path") or None
        # sec_epoch -> count (sparse; pruned to last _window+60s of keys)
        self._per_sec: dict[int, int] = defaultdict(int)
        self._last: BaselineResult | None = None

    def record(self, now: float | None = None) -> None:
        s = int(time.time() if now is None else now)
        c = s - self._window - 120  # a little slack before culling
        with self._lock:
            self._per_sec[s] += 1
            for k in list(self._per_sec.keys()):
                if k < c:
                    del self._per_sec[k]

    def _vector_last(
        self,
        end_sec: int,
    ) -> list[int]:
        start = end_sec - self._window
        with self._lock:
            return [int(self._per_sec.get(s, 0)) for s in range(start, end_sec)]

    def recompute(self, now: float | None = None) -> BaselineResult:
        now = time.time() if now is None else now
        end = int(now)
        vals_full = self._vector_last(end)
        h_now = datetime.fromtimestamp(end, tz=timezone.utc).hour
        idx_ch: list[int] = []
        for i, se in enumerate(range(end - self._window, end)):
            if datetime.fromtimestamp(se, tz=timezone.utc).hour == h_now:
                idx_ch.append(i)
        use_ch = len(idx_ch) >= self._min_samples_ch
        if use_ch:
            vals = [vals_full[i] for i in idx_ch]
            src = "current_hour"
        else:
            vals = vals_full
            src = "full_window"
        m, s = _mean_std_sample(vals)
        m = max(m, self._floor)
        s = max(s, self._min_std)
        total = sum(vals_full)
        res = BaselineResult(
            effective_mean=m,
            effective_std=s,
            source=src,
            n_samples=len(vals),
            total_requests_in_window=total,
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
        # [timestamp] ACTION ip | condition | rate | baseline | duration
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


# --- optional thread start helper from main (kept here to keep main thin) ---


def start_baseline_recompute_thread(
    baseline: RollingBaseline,
    should_stop: threading.Event,
) -> None:
    """daemon thread: sleep in chunks so ``should_stop`` is noticed quickly enough"""

    def _run() -> None:
        # small first delay so a few log lines exist before first recompute
        t = 2.0
        while not should_stop.is_set():
            if should_stop.wait(timeout=t):
                break
            t = float(baseline.recompute_interval)
            try:
                r = baseline.recompute()
                baseline.append_audit_recalc(r)
                log.info(
                    "baseline: mean=%.4f std=%.4f src=%s n=%d total30m=%d",
                    r.effective_mean,
                    r.effective_std,
                    r.source,
                    r.n_samples,
                    r.total_requests_in_window,
                )
            except Exception:  # noqa: BLE001
                log.exception("baseline recompute failed")

    th = threading.Thread(target=_run, name="baseline-recompute", daemon=True)
    th.start()
