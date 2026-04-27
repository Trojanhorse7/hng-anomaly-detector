"""HNG anomaly detector — entrypoint (tail logs, sliding windows, rolling baseline)."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

import detector as det
from actions import handle_detection
from env_expand import expand_env_placeholders
from baseline import RollingBaseline, start_baseline_recompute_thread
from dashboard import build_state_json, start_dashboard
from metrics_runtime import RuntimeMetrics
from monitor import AccessLogMonitor
from notifier import load_notifier_config
from unbanner import BanManager
from windows import SlidingWindows


_stop = threading.Event()


def _handle_sig(_sig: int, _frame: object) -> None:
    _stop.set()
    logging.info("signal — stopping")
    sys.exit(0)


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def load_config() -> dict:
    cfg_path = Path(os.environ.get("HNG_CONFIG", "config.yaml"))
    if not cfg_path.is_file():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        sys.exit(1)
    with cfg_path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return expand_env_placeholders(raw if raw is not None else {})


def main() -> None:
    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)
    setup_logging()
    cfg = load_config() or {}
    log_path = cfg.get("log_path", "/var/log/nginx/hng-access.log")
    start_at_end = bool(cfg.get("start_at_end", True))
    window_s = float(cfg.get("window_seconds", 60.0))
    sweep_s = float(cfg.get("sweep_interval_seconds", 1.0))
    win = SlidingWindows(window_seconds=window_s, sweep_interval_seconds=sweep_s)
    bl = RollingBaseline(cfg)
    metrics = RuntimeMetrics()
    notifier_cfg = load_notifier_config(cfg)
    audit_path = str(cfg.get("audit_log_path") or "")
    ban_state_path = str(cfg.get("ban_state_path") or "/app/data/ban_state.json")
    ban_tick = float(cfg.get("unbanner_tick_seconds", 3.0))
    ban_mgr = BanManager(
        ban_state_path,
        audit_path or None,
        notifier_cfg.webhook_url,
        tick_interval=ban_tick,
    )
    ban_mgr.start_thread(_stop)
    dcfg = det.load_detection_config(cfg)
    start_baseline_recompute_thread(bl, _stop)
    last_det_log = [0.0]  # throttle info lines
    last_global_slack_ts = [0.0]
    actions_enabled = ((cfg.get("actions") or {}).get("enabled") is not False)
    global_cd = float((cfg.get("actions") or {}).get("global_notify_cooldown_seconds", 120.0))

    dash_cfg = cfg.get("dashboard") or {}
    if dash_cfg.get("enabled", True):
        _pi = float(dash_cfg.get("push_interval_seconds", 2.5))
        push_interval_s = max(0.2, min(_pi, 3.0))
        start_dashboard(
            str(dash_cfg.get("bind_host", dash_cfg.get("host", "0.0.0.0"))),
            int(dash_cfg.get("port", 8080)),
            lambda: build_state_json(
                win=win,
                bl=bl,
                ban_mgr=ban_mgr,
                metrics=metrics,
                window_s=window_s,
            ),
            push_interval_s=push_interval_s,
        )

    def on_event(ev: dict) -> None:
        st = int(ev["status"])
        is_err = 400 <= st < 600
        bl.record(is_error=is_err)
        win.record(ev["source_ip"], status=st)
        g = win.global_count()
        ig = win.ip_count(ev["source_ip"])
        g_rps = g / window_s
        i_rps = ig / window_s
        metrics.bump()
        sn = det.evaluate(bl.last, win, ev["source_ip"], window_s, dcfg)
        if actions_enabled:
            handle_detection(
                sn=sn,
                bl=bl,
                ev=ev,
                ban_mgr=ban_mgr,
                webhook_url=notifier_cfg.webhook_url,
                global_cooldown_s=global_cd,
                last_global_ts=last_global_slack_ts,
            )
        if sn.global_anomaly or sn.ip_anomaly:
            if time.time() - last_det_log[0] > 1.0:
                last_det_log[0] = time.time()
                logging.warning(
                    "det: global=%s ip=%s | zg=%.2f zi=%.2f | %s",
                    sn.global_anomaly,
                    sn.ip_anomaly,
                    sn.z_global,
                    sn.z_ip,
                    sn.reason,
                )
        # one line per request + sliding-window stats for the configured window
        det_note = f" det=G{int(sn.global_anomaly)}I{int(sn.ip_anomaly)}e{int(sn.error_surge)}"
        print(
            f"event: ip={ev['source_ip']} {ev['method']} {ev['path']} -> "
            f"{ev['status']} size={ev['response_size']}"
            f" | w{int(window_s)}s: global={g}({g_rps:.2f}/s) this_ip={ig}({i_rps:.2f}/s){det_note}",
            flush=True,
        )

    m = AccessLogMonitor(
        log_path,
        on_event=on_event,
        start_at_end=start_at_end,
    )
    
    logging.info("daemon up — tailing %s", log_path)
    m.run_forever()


if __name__ == "__main__":
    main()
