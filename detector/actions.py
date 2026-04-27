"""React to detection: Slack + ban (no iptables for global-only)."""

from __future__ import annotations

import logging
import time
from typing import Any

import detector as det_engine
import notifier
from baseline import RollingBaseline
from unbanner import BanManager

log = logging.getLogger(__name__)


def handle_detection(
    *,
    sn: Any,
    bl: RollingBaseline | None,
    ev: dict,
    ban_mgr: BanManager,
    webhook_url: str,
    global_cooldown_s: float,
    last_global_ts: list[float],
) -> None:
    if bl is None:
        return
    br = bl.last
    if br is None:
        return
    if sn.global_anomaly:
        cause = det_engine.global_anomaly_cause(sn, br)
        if cause == "none":
            return
        now = time.time()
        if now - last_global_ts[0] >= global_cooldown_s:
            last_global_ts[0] = now
            notifier.notify_global_anomaly(
                webhook_url,
                condition=cause,
                rate=sn.g_rps,
                mean=br.effective_mean,
                std=br.effective_std,
            )
    if sn.ip_anomaly:
        cause = det_engine.ip_anomaly_cause(sn, br)
        if cause == "none":
            return
        ip = ev["source_ip"]
        try:
            ban_mgr.try_ban_from_anomaly(
                ip,
                condition=cause,
                rate=sn.ip_rps,
                mean=br.effective_mean,
                std=br.effective_std,
            )
        except Exception:  # noqa: BLE001
            log.exception("ban flow for %s", ip)
