"""
Anomaly decision: compare live RPS (60s) to rolling baseline (30m) mean/std.
Global + per-IP use the same global baseline (task: rate vs "baseline mean" + z-score).

If IP error RPS (4xx/5xx) exceeds N × baseline error mean, use tighter z / rate multipliers.
"""

from __future__ import annotations

from dataclasses import dataclass

from baseline import BaselineResult
from windows import SlidingWindows


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    z_threshold: float
    z_threshold_tight: float
    rate_multiplier: float
    rate_multiplier_tight: float
    error_surge_multiplier: float
    # below this baseline error RPS, do not treat as error surge (avoid noise when err mean ~0)
    min_baseline_error_for_surge: float


def load_detection_config(cfg: dict) -> DetectionConfig:
    d = cfg.get("detection") or {}
    return DetectionConfig(
        z_threshold=float(d.get("z_threshold", 3.0)),
        z_threshold_tight=float(d.get("z_threshold_tight", 2.0)),
        rate_multiplier=float(d.get("rate_multiplier", 5.0)),
        rate_multiplier_tight=float(d.get("rate_multiplier_tight", 3.0)),
        error_surge_multiplier=float(d.get("error_surge_multiplier", 3.0)),
        min_baseline_error_for_surge=float(d.get("min_baseline_error_for_surge", 0.0001)),
    )


def z_score(observed: float, mean: float, std: float) -> float:
    """How many 'sigmas' away from the baseline mean; std is floored in baseline."""
    if std <= 0.0:
        return 0.0
    return (observed - mean) / std


def _error_surge_active(
    b: BaselineResult,
    ip_error_rps: float,
    d: DetectionConfig,
) -> bool:
    if b.error_effective_mean < d.min_baseline_error_for_surge:
        return False
    return ip_error_rps > d.error_surge_multiplier * b.error_effective_mean


@dataclass(frozen=True, slots=True)
class DetectionSnapshot:
    global_anomaly: bool
    ip_anomaly: bool
    z_global: float
    z_ip: float
    g_rps: float
    ip_rps: float
    error_surge: bool
    use_z: float
    use_rate_mult: float
    reason: str


def evaluate(
    b: BaselineResult | None,
    win: SlidingWindows,
    source_ip: str,
    window_s: float,
    d: DetectionConfig,
) -> DetectionSnapshot:
    if b is None:
        return DetectionSnapshot(
            global_anomaly=False,
            ip_anomaly=False,
            z_global=0.0,
            z_ip=0.0,
            g_rps=0.0,
            ip_rps=0.0,
            error_surge=False,
            use_z=d.z_threshold,
            use_rate_mult=d.rate_multiplier,
            reason="no_baseline_yet",
        )
    mu = b.effective_mean
    sig = b.effective_std
    g_rps = win.global_rps()
    ip_rps = win.ip_rps(source_ip)
    ip_e_rps = win.ip_error_rps(source_ip)
    z_g = z_score(g_rps, mu, sig)
    z_i = z_score(ip_rps, mu, sig)
    surge = _error_surge_active(b, ip_e_rps, d)
    z_t = d.z_threshold_tight if surge else d.z_threshold
    rm = d.rate_multiplier_tight if surge else d.rate_multiplier
    mpos = max(mu, 1e-12)
    g_hit = (z_g > z_t) or (g_rps > rm * mpos)
    i_hit = (z_i > z_t) or (ip_rps > rm * mpos)
    r = f"mu={mu:.4f} zg={z_g:.2f} zi={z_i:.2f} surge={surge}"
    return DetectionSnapshot(
        global_anomaly=g_hit,
        ip_anomaly=i_hit,
        z_global=z_g,
        z_ip=z_i,
        g_rps=g_rps,
        ip_rps=ip_rps,
        error_surge=surge,
        use_z=z_t,
        use_rate_mult=rm,
        reason=r,
    )
